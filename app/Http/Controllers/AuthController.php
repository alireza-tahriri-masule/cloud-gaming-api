<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $request->validate([
            'name'     => 'required|string|max:255',
            'email'    => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
        ]);

        $user = User::create([
            'name'     => $request->name,
            'email'    => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = auth()->login($user);

        return response()->json([
            'data' => $user,
            'status' => [
                'code'    => 201,
                'message' => 'User registered successfully.',
            ],
            'authorization' => [
                'token' => $token,
                'type'  => 'Bearer',
            ],
        ]);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email'    => 'required|string|email',
            'password' => 'required|string|min:8',
        ]);

        $credentials = $request->only(['email', 'password']);

        $token = auth()->attempt($credentials);

        if (!$token) {
            return response()->json([
                'data' => null,
                'status' => [
                    'code'    => 401,
                    'message' => 'Invalid email or password.',
                ],
            ]);
        }

        $user = auth()->user();

        return response()->json([
            'data' => $user,
            'status' => [
                'code'    => 200,
                'message' => 'Login successful.',
            ],
            'authorization' => [
                'token' => $token,
                'type'  => 'Bearer',
            ],
        ]);
    }

    public function logout() {
        Auth::logout();

        return response()->json([
            'data' => null,
            'status' => [
                'code'    => 200,
                'message' => 'Logout successful.',
            ]
        ]);
    }

    public function refresh() {
        return response()->json([
            'data' => auth()->user(),
            'authorization' => [
                'token' => auth()->refresh(),
                'type'  => 'Bearer',
            ]
        ]);
    }
}
