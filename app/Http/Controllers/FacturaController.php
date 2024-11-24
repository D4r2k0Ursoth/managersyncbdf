<?php

namespace App\Http\Controllers;
use App\Models\Usuario; 
use App\Mail\FacturaEnviada;


use Illuminate\Support\Facades\Mail;

use Illuminate\Support\Facades\Cache;
use App\Models\Empresa; 
use App\Models\Factura;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Models\NumeroComprobante;
use Illuminate\Support\Facades\Log;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
class FacturaController extends Controller

{
//---------------------------------------------------------------------------------------------
    public function obtenerToken()
{
    $client = new \GuzzleHttp\Client();
    $url = "https://idp.comprobanteselectronicos.go.cr/auth/realms/rut-stag/protocol/openid-connect/token";
    
    try {
        $response = $client->post($url, [
            'form_params' => [
                'client_id' => 'api-stag',
                'username' => 'cpf-06-0408-0688@stag.comprobanteselectronicos.go.cr',
                'password' => 'oL+?Qx:hm-i|DD]1T1=+',
                'grant_type' => 'password',
            ],
            'headers' => [
                'Content-Type' => 'application/x-www-form-urlencoded; charset=utf-8',
            ]
        ]);
        
        $data = json_decode($response->getBody(), true);
        
        if (isset($data['access_token'])) {
            // Almacena el token en caché por 15 minutos (ajusta según necesites)
            Cache::put('hacienda_token', $data['access_token'], now()->addMinutes(15));

            Log::info('Token recibido y guardado en caché', ['access_token' => $data['access_token']]);
            return response()->json(['access_token' => $data['access_token']]);
        } else {
            Log::error('Token no recibido en la respuesta');
            return response()->json(['error' => 'Token no recibido en la respuesta'], 500);
        }
    } catch (RequestException $e) {
        Log::error('Error obteniendo el token: ' . $e->getMessage());
        return response()->json(['error' => 'Error obteniendo el token: ' . $e->getMessage()], 500);
    }
}

//--------------------------------------------------------------------------------------
public function enviarFactura($xmlData)
{
    ob_clean(); // Limpia el buffer de salida anterior
    $client = new \GuzzleHttp\Client();
    $url = "https://api-sandbox.comprobanteselectronicos.go.cr/recepcion/v1/recepcion/";

    // Obtener el token desde la caché
    $token = Cache::get('hacienda_token');
    if (!$token) {
        return response()->json(['error' => 'Token no disponible. Obtén un nuevo token.'], 500);
    }

    try {
        // Cargar el archivo .p12 y procesarlo
        $p12Path = storage_path('app/certificates/060408068818.p12');
        $p12Password = '1234';
        
        $p12Content = file_get_contents($p12Path);
        if (!$p12Content) {
            throw new \Exception('No se pudo leer el archivo .p12.');
        }
        
        $certs = [];
        if (!openssl_pkcs12_read($p12Content, $certs, $p12Password)) {
            Log::error('Error procesando el archivo .p12. Verifica el archivo y la contraseña.');
            throw new \Exception('No se pudo procesar el archivo .p12. Verifica la contraseña.');
        }
        
        // Verifica que contenga los datos necesarios
        if (!isset($certs['pkey']) || !isset($certs['cert'])) {
            Log::error('El archivo .p12 no contiene los datos esperados.');
            throw new \Exception('El archivo .p12 no contiene clave privada o certificado.');
        }
        
        $privateKey = $certs['pkey']; // Clave privada
        $certificate = $certs['cert']; // Certificado público
        
        if (!$privateKey || !$certificate) {
            throw new \Exception('El archivo .p12 no contiene clave privada o certificado.');
        }

        // Cargar el XML en un objeto DOM
        $xmlDoc = new \DOMDocument();
        $xmlDoc->loadXML($xmlData);

        // Agregar atributos necesarios para la firma
        $xmlDoc->documentElement->setAttribute('xmlns:ds', 'http://www.w3.org/2000/09/xmldsig#');
     

        // Crear el objeto de firma
        $objXMLSecDSig = new \RobRichards\XMLSecLibs\XMLSecurityDSig();
        $objXMLSecDSig->setCanonicalMethod('http://www.w3.org/2001/10/xml-exc-c14n#');

        // Agregar la referencia a los datos firmados
        $objXMLSecDSig->addReference(
            $xmlDoc,
            \RobRichards\XMLSecLibs\XMLSecurityDSig::SHA256,
            [
                'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
                'http://www.w3.org/2001/10/xml-exc-c14n#'
            ],
            ['id_name' => 'ID']
        );

        // Crear el nodo de propiedades firmadas (XAdES)


        
        $signedProperties = $xmlDoc->createElement('xades:SignedProperties');
        $signedProperties->setAttribute('Id', 'SignedProperties');

        $signedProperties->setAttribute('xmlns:xades', 'http://uri.etsi.org/01903/v1.3.2#');

        // Añadir la fecha y hora de la firma
        $signingTime = $xmlDoc->createElement('xades:SigningTime', gmdate('Y-m-d\TH:i:s\Z'));
        $signedProperties->appendChild($signingTime);

        // Información del certificado
        $signingCertificate = $xmlDoc->createElement('xades:SigningCertificate');
        $certDigest = $xmlDoc->createElement('xades:CertDigest');
        $digestMethod = $xmlDoc->createElement('ds:DigestMethod');
        $digestMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
        $certDigest->appendChild($digestMethod);
        $digestValue = $xmlDoc->createElement('ds:DigestValue', base64_encode(hash('sha256', $certificate, true)));
        $certDigest->appendChild($digestValue);
        $signingCertificate->appendChild($certDigest);
        $signedProperties->appendChild($signingCertificate);

        // Política de firma
        $policy = $xmlDoc->createElement('xades:SignaturePolicyIdentifier');
        $policyId = $xmlDoc->createElement('xades:SignaturePolicyId');
        $policyId->appendChild($xmlDoc->createElement('xades:SigPolicyId', 'Política por defecto Hacienda'));
        $policyDigest = $xmlDoc->createElement('xades:SigPolicyHash');
        $policyDigestMethod = $xmlDoc->createElement('ds:DigestMethod');
        $policyDigestMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
        $policyDigestValue = $xmlDoc->createElement('ds:DigestValue', base64_encode(hash('sha256', 'Política Hacienda', true)));
        $policyDigest->appendChild($policyDigestMethod);
        $policyDigest->appendChild($policyDigestValue);
        $policyId->appendChild($policyDigest);
        $policy->appendChild($policyId);
        $signedProperties->appendChild($policy);

        // Referencia de las propiedades firmadas
        $objXMLSecDSig->addReference(
            $signedProperties,
            \RobRichards\XMLSecLibs\XMLSecurityDSig::SHA256,
            ['http://www.w3.org/2001/10/xml-exc-c14n#'],
            ['URI' => '#SignedProperties']
        );

        // Crear la clave de firma
        $objKey = new \RobRichards\XMLSecLibs\XMLSecurityKey(
            \RobRichards\XMLSecLibs\XMLSecurityKey::RSA_SHA256,
            ['type' => 'private']
        );
        $objKey->loadKey($privateKey);

        // Firmar el XML
        $objXMLSecDSig->sign($objKey);

        // Añadir el certificado público al XML firmado
        $objXMLSecDSig->add509Cert($certificate);

        // Insertar la firma en el documento XML
        $objXMLSecDSig->appendSignature($xmlDoc->documentElement);

        // Convertir el XML firmado a cadena
        $signedXmlData = $xmlDoc->saveXML();




          // **Validar el XML firmado contra el archivo XSD**
          $xsdPath = storage_path('app/schemas/TiqueteElectronico_V4.3.xsd'); // Ruta al archivo XSD

          if (!$xmlDoc->schemaValidate($xsdPath)) {
              throw new \Exception('El XML no es válido según el esquema XSD.');
          }



        // Intentar enviar el correo con la factura firmada
        try {
            Mail::to('destinatario@example.com')->send(new FacturaEnviada($signedXmlData));
            Log::info('Factura enviada por correo');
        } catch (\Exception $e) {
            Log::error('Error enviando la factura por correo: ' . $e->getMessage());
        }







        

        // Enviar el XML firmado a Hacienda
        $response = $client->post($url, [
            'headers' => [
                'Authorization' => 'Bearer ' . $token,
                'Content-Type' => 'application/xml',
            ],
            'body' => $signedXmlData,
        ]);
        
        // Capturar la respuesta
        $responseBody = $response->getBody()->getContents();
        $statusCode = $response->getStatusCode();
        Log::info("Código de respuesta HTTP: $statusCode");
        Log::info("Cuerpo de la respuesta: $responseBody");
    
        return response()->json(['respuesta' => $responseBody]);
    } catch (\Exception $e) {
        Log::error('Error enviando la factura: ' . $e->getMessage());
        Log::info('Código de respuesta HTTP: ' . $e->getCode());
        Log::info('Cuerpo de la respuesta: ' . $e->getMessage());
        return response()->json(['error' => 'Error enviando la factura: ' . $e->getMessage()], 500);
    }
}


//---------------------------------------------------------------------------------------------

    
    public function index()
    {
        return response()->json(Factura::with(['cliente', 'proveedor', 'usuario', 'detalles'])->get(), 200);
    }

    /**
     * Almacena una nueva factura.
     */
    public function store(Request $request)
{
   
    $validator = Validator::make($request->all(), [
        'empresa_id' => 'required|exists:empresas,id',
        'cliente_id' => 'nullable|exists:clientes,id',
        'proveedor_id' => 'nullable|exists:proveedors,id',
        'usuario_id' => 'required|exists:usuarios,id',
        'fecha_emision' => 'required|date',
        'fecha_vencimiento' => 'nullable|date',
        'total' => 'required|numeric',
        'tipo' => 'required|in:venta,compra',
        'estado' => 'in:Emitida,Pagada,Cancelada',
        'xml_data' => 'nullable|string',
        'detalles' => 'required|array', // Asegúrate de que detalles es un array
        'detalles.*.codigo_cabys' => 'required|string',
        'detalles.*.codigo_producto' => 'required|string',
        'detalles.*.cantidad' => 'required|numeric',
        'detalles.*.descripcion' => 'required|string',
        'detalles.*.precio_unitario' => 'required|numeric',
        'detalles.*.subtotal' => 'required|numeric',
        'detalles.*.totalIVA' => 'required|numeric',
        'detalles.*.totalVenta' => 'required|numeric',
        'detalles.*.unidad_medida' => 'required|string',
    ]);

    if ($validator->fails()) {
        return response()->json(['errors' => $validator->errors()], 422);
    }


$usuario = Usuario::find($request->usuario_id);

if ($usuario && $usuario->empresa) {

    $cedula_empresa = $usuario->empresa->cedula_empresa; 
} else {
  
    $cedula_empresa = null; 
}


    // Generar el código único y el número de comprobante
    $codigoData = $this->generarCodigoUnico(001, 001, 04, $cedula_empresa);

    // Crear la factura con el código único y el número de comprobante
    $factura = Factura::create(array_merge($request->all(), [
        'codigo_unico' => $codigoData['codigo_unico'], 
        'numero_comprobante' => $codigoData['numero_comprobante'] 
    ]));

   
   $xmlData = $this->generateXml($factura, $request->detalles);
   $factura->xml_data = $xmlData;
   $factura->save(); 

   // Llamar al método enviarFactura con el XML generado
   $this->enviarFactura($xmlData);


    return response()->json($factura, 201);
    
}
//----------------------------------------------------------------------------------------------------------

    /**
     * Muestra una factura específica.
     */
    public function show($id)
    {
        $factura = Factura::with(['cliente', 'proveedor', 'usuario', 'detalles'])->find($id);

        if (!$factura) {
            return response()->json(['message' => 'Factura no encontrada'], 404);
        }

        return response()->json($factura, 200);
    }

    /**
     * Actualiza una factura existente.
     */
    public function update(Request $request, $id)
    {
        $factura = Factura::find($id);

        if (!$factura) {
            return response()->json(['message' => 'Factura no encontrada'], 404);
        }

        // Validación de datos
        $validator = Validator::make($request->all(), [
            'cliente_id' => 'nullable|exists:clientes,id',
            'proveedor_id' => 'nullable|exists:proveedors,id',
            'usuario_id' => 'required|exists:usuarios,id',
            'fecha_emision' => 'required|date',
            'fecha_vencimiento' => 'nullable|date',
            'total' => 'required|numeric',
            'tipo' => 'required|in:venta,compra',
            'estado' => 'in:Emitida,Pagada,Cancelada',
            'codigo_unico' => 'required|string|unique:faturas,codigo_unico,' . $id,
            'xml_data' => 'nullable|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        // Actualizar la factura
        $factura->update($request->all());
        $detalles = $request->detalles;
        // Generar el XML nuevamente si es necesario
        $xmlData = $this->generateXml($factura);
        $factura->xml_data = $xmlData;
        $factura->save(); // Actualiza la factura con el nuevo XML

        return response()->json($factura, 200);
    }

    /**
     * Elimina una factura existente.
     */
    public function destroy($id)
    {
        $factura = Factura::find($id);

        if (!$factura) {
            return response()->json(['message' => 'Factura no encontrada'], 404);
        }

        $factura->delete();
        return response()->json(['message' => 'Factura eliminada correctamente'], 204);
    }

    //-----------------------------------------------------------------------------------------


    function generarNumeroConsecutivoTiquete($codigoPais = '001', $codigoSucursal = '000', $puntoVenta = '01', $tipoComprobante = '04') { 
        // Obtener el último número de comprobante desde la base de datos
        $numeroComprobante = NumeroComprobante::first();
        
        if (!$numeroComprobante) {
            // Si no existe, crear uno nuevo con el último número en 1
            $numeroComprobante = NumeroComprobante::create(['ultimo_numero' => 1]);
            $ultimoNumero = 1;
        } else {
            // Guardar el último número
            $ultimoNumero = $numeroComprobante->ultimo_numero;
        }
    
        // Formateamos cada componente al tamaño requerido
        $codigoPaisFormateado = str_pad($codigoPais, 3, '0', STR_PAD_LEFT);         // 3 dígitos
    
        // Aseguramos que el código de sucursal siempre sea '000'
        $codigoSucursalFormateado = '000';  // Siempre forzamos que sea '000'
    
        $puntoVentaFormateado = str_pad($puntoVenta, 2, '0', STR_PAD_LEFT);          // 2 dígitos
        $tipoComprobanteFormateado = str_pad($tipoComprobante, 2, '0', STR_PAD_LEFT); // 2 dígitos
        $consecutivoFormateado = str_pad($ultimoNumero, 10, '0', STR_PAD_LEFT);      // 10 dígitos
    
        // Incrementar el consecutivo para la próxima llamada
        $nuevoNumero = $ultimoNumero + 1;
    
        // Actualizar el número consecutivo en la base de datos
        $numeroComprobante->ultimo_numero = $nuevoNumero;
        $numeroComprobante->save();
    
        // Retornar el número formateado con sucursal siempre como '000'
        return $codigoPaisFormateado . $codigoSucursalFormateado . $puntoVentaFormateado . $tipoComprobanteFormateado . $consecutivoFormateado;
    }
    //-----------------------------------------------------------------------------------------------------
    
    /**
     * Genera un código único de 50 caracteres para la factura.
     */
   

     private function generarCodigoUnico($sucursal, $terminal, $tipo, $cedula_empresa) {
      
      
    
        $pais = "506"; // Código del país, Costa Rica
        $fecha = now()->format('dmy'); // Cambiado a 'dmyHis' para incluir solo los últimos dos dígitos del año
    
        $situacion = "1";
       
    
        $codigoSeguridad = str_pad(rand(0, 99999999), 8, '0', STR_PAD_LEFT);
        $cedula_empresa = str_pad($cedula_empresa, 12, '0', STR_PAD_LEFT);
    
        // Llamada a la función generarNumeroConsecutivoTiquete con el valor actual de consecutivo
        $numeroConsecutivo = $this->generarNumeroConsecutivoTiquete("001", $sucursal, $terminal, $tipo);
    
        // Construir el código único incluyendo la cedula_empresa
        $codigoUnico = $pais . $fecha . $cedula_empresa . $numeroConsecutivo .$situacion. $codigoSeguridad;
    
        // Formato a 50 caracteres
        $codigoUnicoFormateado = str_pad($codigoUnico, 50, '0');
    
       
        $numeroComprobante = $numeroConsecutivo;
    
        return [
            'codigo_unico' => $codigoUnicoFormateado,
            'numero_comprobante' => $numeroComprobante,
        ];
    }
    
    

    /**
     * Genera el XML para la factura.
     */
    private function generateXml($factura, $detallesFactura) {
      
    // Limpia cualquier salida previa al XML
    ob_clean(); // Limpia el buffer de salida
    ob_start(); // Inicia un nuevo buffer limpio

 

        //  cargar las relaciones del usuario, cliente, y los detalles de la factura
        $factura->load(['usuario', 'detalles']);
        
  
        $xml = new \SimpleXMLElement(
            '<TiqueteElectronico   xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns="https://cdn.comprobanteselectronicos.go.cr/xml-schemas/v4.3/tiqueteElectronico"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="https://cdn.comprobanteselectronicos.go.cr/xml-schemas/v4.3/tiqueteElectronico https://cdn.comprobanteselectronicos.go.cr/xml-schemas/v4.3/tiqueteElectronico.xsd
        http://www.w3.org/2000/09/xmldsig# https://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd"/>'
        );
        $xmlWithHeader = '<?xml version="1.0" encoding="UTF-8"?>' . "\n" . $xml->asXML();

// Mostrar o guardar el XML
echo $xmlWithHeader; // O guardarlo en un archivo
file_put_contents('TiqueteElectronico.xml', $xmlWithHeader);
  
        $xml->addChild('Clave', $factura->codigo_unico);
        $codigoActividad = $factura->usuario->empresa->codigo_actividad ?? '000000'; // Valor por defecto si no existe

        // Nodo Código de Actividad
        $xml->addChild('CodigoActividad', $codigoActividad);
        $xml->addChild('NumeroConsecutivo', $factura->numero_comprobante);
        $fechaEmision = new \DateTime($factura->fecha_emision); 
$fechaEmision->setTimezone(new \DateTimeZone('America/Costa_Rica')); 
$fechaEmisionFormatted = $fechaEmision->format('Y-m-d\TH:i:sP'); 

$xml->addChild('FechaEmision', $fechaEmisionFormatted); 

        
        // Nodo 2: Emisor
        $emisor = $xml->addChild('Emisor');

        // Nodo Nombre
        $emisor->addChild('Nombre', $factura->usuario->empresa->nombre ?? '');
        
        // Nodo Identificacion (con subnodos Tipo y Numero)
        $identificacion = $emisor->addChild('Identificacion');
        $tipo_cedula = $factura->usuario->empresa->empresa;
        $identificacion->addChild('Tipo', $tipo_cedula === 'fisica' ? '01' : ($tipo_cedula === 'juridica' ? '02' : ''));
        $identificacion->addChild('Numero', $factura->usuario->empresa->cedula_empresa ?? '');
        
        // Nodo Ubicacion (con subnodos Provincia, Canton, Distrito, OtrasSenas)
        $ubicacion = $emisor->addChild('Ubicacion');

        // Asegurarte de que Provincia, Cantón y Distrito siempre tengan 2 dígitos
        $provincia = str_pad($factura->usuario->empresa->provincia ?? '', 1, '0', STR_PAD_LEFT);
        $canton = str_pad($factura->usuario->empresa->canton ?? '', 2, '0', STR_PAD_LEFT);
        $distrito = str_pad($factura->usuario->empresa->distrito ?? '', 2, '0', STR_PAD_LEFT);
        
        // Agregar los valores formateados
        $ubicacion->addChild('Provincia', $provincia);
        $ubicacion->addChild('Canton', $canton);
        $ubicacion->addChild('Distrito', $distrito);
        $ubicacion->addChild('OtrasSenas', $factura->usuario->empresa->otras_senas ?? '');
        
        // Nodo Telefono (con subnodos CodigoPais y NumTelefono)
        $telefono = $emisor->addChild('Telefono');
        $telefono->addChild('CodigoPais', '506'); 
        $telefono->addChild('NumTelefono', $factura->usuario->empresa->telefono ?? '');
        
        // Nodo CorreoElectronico
        $emisor->addChild('CorreoElectronico', $factura->usuario->empresa->correo ?? '');
        
        $xml->addChild('CondicionVenta', '01'); // 01 para contado, 02 para crédito
        
        $medioPago = $xml->addChild('MedioPago', '01');
       
        // Nodo 3: Cliente
       // $cliente = $xml->addChild('Receptor');
       // if ($factura->cliente) {
       //     $cliente->addChild('nombre', $factura->cliente->nombre ?? '');
       //     $cliente->addChild('email', $factura->cliente->email ?? '');
       // } else {
       //     $cliente->addChild('nombre', 'Desconocido');
      //      $cliente->addChild('email', 'no-disponible@ejemplo.com');
      //  }
        
      $detalles = $xml->addChild('DetalleServicio'); // Solo un nodo DetalleServicio

      // Asume que tienes un porcentaje de IVA que aplica a todos los productos
      $ivaPorcentaje = 0.13; // 13% de IVA, ajusta según lo necesario
      $totalIVA = 0; // Acumulador para el total de IVA
      $subtotalTotal = 0; // Acumulador para el subtotal total (sin IVA)
      $totalVentaTotal = 0; // Acumulador para el total de venta (con IVA)
      
      $lineaCount = 0; // Contador de las líneas de detalle
      
      foreach ($detallesFactura as $detalle) {
          // Limitar el número de líneas de detalle a 1000
          if ($lineaCount >= 1000) {
              break; // Detener el ciclo si ya se han agregado 1000 líneas
          }
      
          // Calcula el subtotal por producto (sin IVA)
          $subtotal = $detalle['cantidad'] * $detalle['precio_unitario'];
      
          // Calcula el IVA por producto (se calcula sobre el subtotal)
          $iva = $subtotal * $ivaPorcentaje;
      
          // Calcula el total por producto (incluyendo IVA)
          $totalVenta = $subtotal + $iva;
      
          // Crear un nodo LineaDetalle para cada producto
          $lineaDetalle = $detalles->addChild('LineaDetalle');
      
          // NumeroLinea: número de la línea en el detalle
          $lineaDetalle->addChild('NumeroLinea', $lineaCount + 1); // Se usa el contador para el número de línea
      
          // Codigo: código del producto o servicio (aquí usaría el código CABYS como ejemplo)
          $lineaDetalle->addChild('Codigo', $detalle['codigo_cabys']);
      
          // CodigoComercial: puede ser un nodo con información adicional del producto
          $codigoComercial = $lineaDetalle->addChild('CodigoComercial');
          $codigoComercial->addChild('Tipo', '01'); // Ajusta según sea necesario, esto es solo un ejemplo
          $codigoComercial->addChild('Codigo', $detalle['codigo_producto'] ?? ''); // Aquí puedes poner el código comercial si tienes
      
          // Cantidad: cantidad de productos o servicios en la línea
          $lineaDetalle->addChild('Cantidad', number_format($detalle['cantidad'], 3, '.', ''));
      
          // UnidadMedida: unidad de medida del producto o servicio
          $lineaDetalle->addChild('UnidadMedida', $detalle['unidad_medida']);
      
          // Detalle: descripción del producto o servicio
          $lineaDetalle->addChild('Detalle', $detalle['descripcion']);
      
          // PrecioUnitario: precio unitario del producto o servicio
          $lineaDetalle->addChild('PrecioUnitario', number_format($detalle['precio_unitario'], 2, '.', ''));
      
          // MontoTotal: monto total por la línea, incluyendo IVA
          $lineaDetalle->addChild('MontoTotal', number_format($totalVenta, 2, '.', ''));
      
          // SubTotal: subtotal de la línea, sin IVA
          $lineaDetalle->addChild('SubTotal', number_format($subtotal, 2, '.', ''));
      
          // Impuesto: información sobre el impuesto, por ejemplo IVA
          $impuestoXml = $lineaDetalle->addChild('Impuesto');
          $impuestoXml->addChild('Codigo', '08'); // Código del impuesto (IVA)
       
          $impuestoXml->addChild('Tarifa', '13.0'); // Tarifa del IVA
          $impuestoXml->addChild('Monto', number_format($iva, 2, '.', ''));
      
          // MontoTotalLinea: monto total de la línea (con IVA)
          $lineaDetalle->addChild('MontoTotalLinea', number_format($totalVenta, 2, '.', ''));
      
          // Acumula los totales para el cálculo final
          $totalIVA += $iva;
          $subtotalTotal += $subtotal;
          $totalVentaTotal += $totalVenta;
      
          // Incrementar el contador de líneas
          $lineaCount++;
      }
      
        $resumenFactura = $xml->addChild('ResumenFactura');
    
    //    $codigoTipoMoneda = $resumenFactura->addChild('CodigoTipoMoneda');
    //$codigoTipoMoneda->addChild('CodigoMoneda', 'CRC');
     // $codigoTipoMoneda->addChild('TipoCambio', '1.00');
      $resumenFactura->addChild('TotalServGravados', number_format($subtotalTotal, 4, '.', ''));
     // $resumenFactura->addChild('TotalServExentos', '0');
    $resumenFactura->addChild('TotalMercanciasGravadas',number_format($subtotalTotal, 4, '.', ''));
     // $resumenFactura->addChild('TotalMercanciasExentas', '0');
     $resumenFactura->addChild('TotalGravado', number_format($subtotalTotal, 4, '.', ''));
     // $resumenFactura->addChild('TotalExento', '0');
    $resumenFactura->addChild('TotalVenta', number_format($subtotalTotal, 4, '.', ''));
     // $resumenFactura->addChild('TotalDescuentos', '0');
    $resumenFactura->addChild('TotalVentaNeta', number_format($subtotalTotal, 4, '.', ''));
    $resumenFactura->addChild('TotalImpuesto', number_format($totalIVA, 4, '.', ''));
    //  $resumenFactura->addChild('TotalOtrosCargos', '0');
    $resumenFactura->addChild('TotalComprobante', number_format($totalVentaTotal, 4, '.', ''));

        
        return $xml->asXML(); // Devuelve el XML como string
    }
    
     }