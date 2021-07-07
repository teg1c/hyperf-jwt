# Install

```shell
composer require tegic/hyperf-jwt
```

# Usage


```php
<?php

declare(strict_types=1);
namespace App\Controller;


use Hyperf\Di\Annotation\Inject;
use Tegic\JWTAuth\JWT;

class IndexController extends AbstractController
{

    /**
     * @Inject()
     * @var JWT
     */
    protected $jwt;

    /**
     * 生成token
     * @return \Lcobucci\JWT\Token|string
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function index()
    {
        $data = [
            'user_id' => 1,
            'platform' => 1
        ];
        $token = $this->jwt->getToken($data);
        return $token;
    }

    /**
     * 检测及解析token
     * @return array
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    public function user()
    {
        $result =  $this->jwt->getParserData();
        $this->jwt->checkToken();
        $result['iat'] = date('Y-m-d H:i:s',$result['iat']);
        $result['nbf'] = date('Y-m-d H:i:s',$result['nbf']);
        $result['exp'] = date('Y-m-d H:i:s',$result['exp']);
        return $result;
    }

    /**
     * 刷新token
     * @return \Lcobucci\JWT\Token|string
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function refreshToken()
    {
        return $this->jwt->refreshToken();

    }
}

```


# Exception

> JWTException   token 不合法

> TokenBackException token 在黑名单内

> TokenValidException  token 过期