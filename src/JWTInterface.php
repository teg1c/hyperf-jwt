<?php

declare(strict_types=1);
/**
 * Jwt For Hyperf
 */
namespace Tegic\JWTAuth;

/**
 * Interface JWTInterface.
 */
interface JWTInterface
{
    public function setSceneConfig(string $scene = 'default', $value = null);

    public function getSceneConfig(string $scene = 'default');

    public function setScene(string $scene);

    public function getScene();
}
