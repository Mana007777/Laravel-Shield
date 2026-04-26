<?php

namespace App;

class MoreHackSurface
{
    public function risky($request)
    {
        return redirect($request->input('next'));
    }

    public function read($request)
    {
        return file_get_contents('/var/www/'. $request->input('file'));
    }

    public function weak()
    {
        $a = md5('password123');
        $b = sha1('secret');
        $token = mt_rand(100000, 999999);
        return [$a, $b, $token];
    }

    public function jwt($request)
    {
        return \Firebase\JWT\JWT::decode($request->input('token'), $key, ['none']);
    }
}
