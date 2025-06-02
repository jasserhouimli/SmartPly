using System.Security.Claims;
using System.Text.Json;
using backend.DTOs;
using backend.Entities;
using backend.Services;
using backend.Settings;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using backend.Services;

public interface IGoogleProvider
{
    Task StoreGoogleTokens(User user, GoogleTokenResponse tokens);
    Task<GoogleTokenResponse> ExchangeCodeForTokens(string code);
    Task<GoogleUserInfo> GetGoogleUserInfo(string idToken);
    string GetAuthorizationUrl();
}

public sealed class GoogleProvider : IGoogleProvider
{
    private readonly UserManager<User> _userManager;
    private readonly IConfiguration _configuration;

    public GoogleProvider(UserManager<User> userManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _configuration = configuration;
    }

    public string GetAuthorizationUrl()
    {
        var clientId = _configuration["Google:ClientId"];
        var redirectUri = _configuration["Google:RedirectUri"];
        var scope = _configuration["Google:Scopes"] ?? "openid profile email https://www.googleapis.com/auth/gmail.readonly";
        var state = Guid.NewGuid().ToString();

        var authUrl = $"https://accounts.google.com/o/oauth2/v2/auth?" +
                     $"client_id={clientId}&" +
                     $"redirect_uri={Uri.EscapeDataString(redirectUri)}&" +
                     $"scope={Uri.EscapeDataString(scope)}&" +
                     $"response_type=code&" +
                     $"state={state}&" +
                     $"access_type=offline&" +
                     $"prompt=consent";

        return authUrl;
    }

    public async Task<GoogleTokenResponse> ExchangeCodeForTokens(string code)
    {
        var clientId = _configuration["Google:ClientId"];
        var clientSecret = _configuration["Google:ClientSecret"];
        var redirectUri = _configuration["Google:RedirectUri"];

        using var httpClient = new HttpClient();

        var tokenRequest = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("code", code),
            new KeyValuePair<string, string>("client_id", clientId!),
            new KeyValuePair<string, string>("client_secret", clientSecret!),
            new KeyValuePair<string, string>("redirect_uri", redirectUri!),
            new KeyValuePair<string, string>("grant_type", "authorization_code")
        });

        var response = await httpClient.PostAsync("https://oauth2.googleapis.com/token", tokenRequest);
        var responseContent = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new Exception($"Failed to exchange code for tokens: {responseContent}");
        }

        var tokenResponse = JsonSerializer.Deserialize<GoogleTokenResponse>(responseContent, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        });

        return tokenResponse!;
    }

    public async Task<GoogleUserInfo> GetGoogleUserInfo(string idToken)
    {
        var payload = await GoogleJsonWebSignature.ValidateAsync(idToken);

        return new GoogleUserInfo
        {
            Id = payload.Subject,
            Email = payload.Email,
            Name = payload.Name,
            Picture = payload.Picture,
            GivenName = payload.GivenName,
            FamilyName = payload.FamilyName
        };
    }

    public async Task StoreGoogleTokens(User user, GoogleTokenResponse tokens)
    {
        // store tokens
        await _userManager.SetAuthenticationTokenAsync(
            user,
            "Google",
            "access_token",
            tokens.AccessToken);

        if (!string.IsNullOrEmpty(tokens.RefreshToken))
        {
            await _userManager.SetAuthenticationTokenAsync(
                user,
                "Google",
                "refresh_token",
                tokens.RefreshToken);
        }

        var expiresAt = DateTime.UtcNow.AddSeconds(tokens.ExpiresIn);
        await _userManager.SetAuthenticationTokenAsync(
            user,
            "Google",
            "expires_at",
            expiresAt.ToString("O"));

        await _userManager.SetAuthenticationTokenAsync(
            user,
            "Google",
            "id_token",
            tokens.IdToken);
    }
}
