<?php

namespace App\Http\Controllers\API;

use App\Actions\Fortify\PasswordValidationRules;
use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    use PasswordValidationRules;
    public function login(Request $request)
    {
        try {
            $request->validate([
                'email' => ['email', 'required'],
                'password' => ['string', 'required']
            ]);

            // cek kredensial
            $credentials = request(['email', 'password']);
            if (!Auth::attempt($credentials)) {
                return ResponseFormatter::error([
                    'message' => 'Unauthorized'
                ], 'Authentication failed', 500);
            }

            // jika hash tidak sesuai berikan error
            $user = User::where('email', $request->email)->first();
            if (!Hash::check($request->password, $user->password, [])) {
                throw new \Exception('Invalid credential');
            }

            // Jika berhasil maka login
            $tokenResult = $user->createToken('authToken')->plainTextToken;
            return ResponseFormatter::success([
                'access_token' =>  $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'Authenticated');
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ], 'Authenticated failed', 500);
        }
    }

    public function register(Request $request)
    {
        try {
            $request->validate([
                'name' => ['string', 'required', 'max:255'],
                'email' => ['string', 'required', 'max:255', 'email', 'unique:users'],
                'password' => $this->passwordRules()
            ]);

            $user = User::where('email', $request->email)->first();
            if ($user) {
                return ResponseFormatter::error([
                    'message' => 'User is exist',
                    'data' => $user
                ], 'Authenticated failed', 403);
            }

            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'address' => $request->address,
                'houseNumber' => $request->houseNumber,
                'phoneNumber' => $request->phoneNumber,
                'city' => $request->city,
                'password' => Hash::make($request->password)
            ]);

            $tokenResult = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ]);
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ], 'Authentication failed', 500);
        }
    }

    public function logut(Request $request)
    {
        $token = $request->user()->currentAccessToken()->delete();

        return ResponseFormatter::success($token, 'Token revoked');
    }

    public function fetch(Request $request)
    {
        return ResponseFormatter::success($request->user(), 'Data user berhasil diambil');
    }

    public function updateProfile(Request $request)
    {
        $data = $request->all();

        $user = Auth::user();
        $user->update($data);

        return ResponseFormatter::success($user, 'Profile updated');
    }

    public function updatePhoto(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'file' => ['required', 'image', 'max:2048']
        ]);

        if ($validator->fails()) {
            return ResponseFormatter::error(
                ['error' => $validator->errors()],
                'Update photo fails',
                401
            );
        }

        if ($request->file('file')) {
            $file = $request->file->store('assets/user', 'public');

            // simpan foto ke database bentuk url
            $user = Auth::user();
            $user->profile_photo_path = $file;
            $user->update();

            return ResponseFormatter::success([$file], 'File successfully uploaded');
        }
    }
}
