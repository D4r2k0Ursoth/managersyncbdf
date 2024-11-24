<?php
namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class FacturaEnviada extends Mailable
{
    use Queueable, SerializesModels;

    public $xmlData;

    /**
     * Create a new message instance.
     *
     * @return void
     */
    public function __construct($xmlData)
    {
        $this->xmlData = $xmlData;
    }

    /**
     * Build the message.
     *
     * @return $this
     */
    public function build()
    {
        return $this->subject('Factura Electrónica')
                    ->view('factura') // Vista del correo
                    ->attachData($this->xmlData, 'factura.xml', [
                        'mime' => 'application/xml',
                    ]);
    }
}
