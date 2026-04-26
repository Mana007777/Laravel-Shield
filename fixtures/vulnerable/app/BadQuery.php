<?php

namespace App;

class BadQuery
{
    public function x()
    {
        return \DB::select('SELECT 1'."x".$id);
    }
}
