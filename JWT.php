<?php

class JWT{
    private $key;
    private $interval = "PT1H"; //1 hora
    private $payload = [];
    private $header = ["alg" => "HS256", "typ" => "JWT"];

    public function __construct($key = null)
    {
        $now = date("Y-m-d H:i:s");
        $valor_aleatorio = strval(rand(0,10000000000000));
        $this->set_key($key ?? $this->generar_hash($now . $valor_aleatorio));
    }
    
    public function set_key($key)
    {
        $this->key = $key;
    }

    private function base64url_encode($data) 
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    
    private function base64url_decode($data) 
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }   
    
    public function agregar_payload($key, $value)
    {
        $this->payload[$key] = $value;
    }

    public function agregar_header($key, $value)
    {
        $this->header[$key] = $value;
    }

    public function obtener_payload()
    {
        return $this->base64url_encode(json_encode($this->payload));
    }

    public function obtener_header()
    {
        return $this->base64url_encode(json_encode($this->header));
    }

    public static function generar_hash($valor_aleatorio)
    {
        return hash("sha256", $valor_aleatorio);
    }

    public function generar_JWT_sumhash($header = null, $payload = null, $algo = null)
    {
        $header = $header ?? $this->obtener_header();
        $payload = $payload ?? $this->obtener_payload();
        return $this->base64url_encode(hash_hmac($algo ?? 'sha256', $header . "." . $payload, $this->key ,true));
    }

    public function obtener_JWT()
    {
        $fecha_creacion = (new DateTimeImmutable())->getTimestamp();
        $fecha_expiracion = (new DateTimeImmutable())->add(new DateInterval($this->interval))->getTimestamp();
        $this->agregar_payload("iat", $fecha_creacion);
        $this->agregar_payload("exp", $fecha_expiracion);
        $sumhash = $this->generar_JWT_sumhash();
        return $this->obtener_header() . "." . $this->obtener_payload() . "." . $sumhash;
    }

    public function validar_JWT($jwt, $validar_expiracion = true)
    {
        $jwt_parts = explode(".", $jwt);
        if(count($jwt_parts) == 3 && $this->generar_JWT_sumhash($jwt_parts[0], $jwt_parts[1]) == $jwt_parts[2])
            if($validar_expiracion){
                $payload = json_decode($this->base64url_decode($jwt_parts[1]), true);
                $now = (new DateTimeImmutable())->getTimestamp();
                if($now <= $payload['exp'])
                    return true;
                else
                    return false;
            }else
                return true;
        else
            return false;

        
    }
           
}

/**
* A continuación un ejemplo de generación de JWT 
*/

//Genero una llave, puede ser un string, en este caso será un HASH de un texto cualquiera
//Podría ser una variable de entorno pre generada
$llave = JWT::generar_hash("SOY UN TEXTO ALEATORIO");

//Asignamos la llave a nuestra clase JWT.  Con esa llave codificará y validará JWTs
$example = new JWT($llave);
//Se agrega una etiqueta para reconocer a los desarrolladores (opcional)
$example->agregar_header("developed", "ID3.cl - alphadx");

//En este caso, este token no tendrá información, sólo será otro valor aleatorio que irá dentro del JWT
$token = JWT::generar_hash("SOY OTRO  TEXTO ALEATORIO");

//Se agrega el token  que creamos a nuestro JWT (para tener algún dato)
$example->agregar_payload("token", $token);

//Se agrega la llave para probar el token (esto es sólo como ejemplo, la llave no debe ser algo que viaje en el token)
$example->agregar_payload("llave", $llave);

//Se genera el JWT
$jwt = $example->obtener_JWT();
echo "TOKEN:\n" . $jwt;

/**
 * Fin de la generación del JWT
 */

echo "\n";
 /**
 * A continuación un ejemplo de la validación de JWT
 */
//Acá la única razón por la que se vuelve a instanciar el objeto $example, es para que veas que recordando la $llave, podrás validar los JWT
$example = new JWT($llave);

if($example->validar_JWT($jwt))
    echo "\nTOKEN válido";
else
    echo "\nTOKEN inválido";
 /**
  * Fin de la validación del JWT
  */
echo "\n";
