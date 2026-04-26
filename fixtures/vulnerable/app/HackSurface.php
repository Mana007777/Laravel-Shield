<?php

namespace App;

class HackSurface
{
    public function dangerous($request): void
    {
        $cmd = $request->input('cmd');
        system('sh -c "'.$cmd.'"');

        $url = $request->input('url');
        file_get_contents($url);

        $payload = $request->input('payload');
        unserialize($payload);

        $file = $request->file('avatar');
        $file->move(public_path('uploads'), $file->getClientOriginalName());

        $apiKey = 'sk_live_1234567890abcdefghij';
    }
}
