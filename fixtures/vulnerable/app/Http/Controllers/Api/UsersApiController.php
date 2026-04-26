<?php

namespace App\Http\Controllers\Api;

use Illuminate\Support\Facades\Http;

class UsersApiController
{
    public function store($request)
    {
        $payload = $request->all();
        return response()->json(['ok' => true, 'payload' => $payload]);
    }

    public function destroy($request)
    {
        dd($request->input('id'));
    }

    public function token($request)
    {
        return Http::withToken($request->input('token'))->get('https://example.com');
    }

    public function cookieLeak()
    {
        return cookie('sid', 'x', 60, '/', null, false, false);
    }
}

