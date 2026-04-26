<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\UsersApiController;

Route::post('/admin/users/create', [UsersApiController::class, 'store']);
Route::delete('/user/profile/delete', [UsersApiController::class, 'destroy']);

