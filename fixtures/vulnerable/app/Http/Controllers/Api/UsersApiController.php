<?php

namespace App\Http\Controllers\Api;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\DB;

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

    public function show($id)
    {
        return DB::table('users')->find($id);
    }

    public function cookieLeak()
    {
        return cookie('sid', 'x', 60, '/', null, false, false);
    }
}

