<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    // Register user
    public function register(Request $request)
    {
        try {
            // Validation des champs
            $attrs = $request->validate([
                'name' => 'required|string',
                'email' => 'required|email|unique:users,email',
                'password' => 'required|min:6|confirmed'
            ]);

            // Création de l'utilisateur
            $user = User::create([
                'name' => $attrs['name'],
                'email' => $attrs['email'],
                'password' => bcrypt($attrs['password'])
            ]);

            // Génération du token
            $token = $user->createToken('secret')->plainTextToken;

            // Réponse JSON
            return response()->json([
                'success' => true,
                'message' => 'Utilisateur enregistré avec succès',
                'data' => [
                    'user' => $user,
                    'token' => $token
                ]
            ], 201);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Erreur de validation',
                'errors' => $e->errors()
            ], 422);
        }
    }

    // Login user
    public function login(Request $request)
    {
        try {
            $attrs = $request->validate([
                'email' => 'required|email',
                'password' => 'required|min:6'
            ]);

            if (!Auth::attempt($attrs)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Identifiants invalides.'
                ], 403);
            }

            $user = Auth::user();
            $token = $user->createToken('secret')->plainTextToken;

            return response()->json([
                'success' => true,
                'message' => 'Connexion réussie',
                'data' => [
                    'user' => $user,
                    'token' => $token
                ]
            ], 200);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Erreur de validation',
                'errors' => $e->errors()
            ], 422);
        }
    }

    // Logout user
    public function logout()
    {
        Auth::user()->tokens()->delete();

        return response()->json([
            'success' => true,
            'message' => 'Déconnexion réussie'
        ], 200);
    }

    // Get user details
    public function user()
    {
        return response()->json([
            'success' => true,
            'data' => [
                'user' => Auth::user()
            ]
        ], 200);
    }
}
