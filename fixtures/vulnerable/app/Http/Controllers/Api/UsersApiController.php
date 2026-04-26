<?php

namespace App\Http\Controllers\Api;

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
        return \Http::withToken($request->input('token'))->get('https://example.com');
    }
}

