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

namespace backend.Controllers;

[ApiController]
[Route("auth")]
[AllowAnonymous]
public sealed class AuthController(
    UserManager<User> userManager,
    TokenProvider tokenProvider,
    ApplicationDbContext applicationDbContext,
    IOptions<JwtAuthOptions> options,
    IGoogleProvider googleProvider,
    IConfiguration configuration) : ControllerBase
{
    private readonly JwtAuthOptions _jwtAuthOptions = options.Value;

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterUserDto registerUserDto)
    {
        var user = new User
        {
            UserName = registerUserDto.Email,
            Email = registerUserDto.Email
        };

        IdentityResult result = await userManager.CreateAsync(user, registerUserDto.Password);

        if (!result.Succeeded)
        {
            // add Proper Error Handling Later
            foreach (var e in result.Errors)
                ModelState.AddModelError(e.Code, e.Description);
            return ValidationProblem(ModelState);
        }

        TokenRequest tokenRequest = new TokenRequest(user.Id, registerUserDto.Email);
        AccessTokensDto accessTokens = tokenProvider.Create(tokenRequest);

        var refreshToken = new RefreshToken
        {
            Id = Guid.CreateVersion7(),
            UserId = user.Id,
            Token = accessTokens.RefreshToken,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(_jwtAuthOptions.RefreshTokenExpirationDays)
        };

        applicationDbContext.RefreshTokens.Add(refreshToken);

        await applicationDbContext.SaveChangesAsync();

        return Ok(accessTokens);
    }
    [HttpPost("login")]
    public async Task<ActionResult<AccessTokensDto>> Login(LoginUserDto loginUserDto)
    {
        User? user = await userManager.FindByEmailAsync(loginUserDto.Email);

        if (user is null || !await userManager.CheckPasswordAsync(user, loginUserDto.Password))
        {
            return Unauthorized();
        }

        TokenRequest tokenRequest = new TokenRequest(user.Id, loginUserDto.Email);
        AccessTokensDto accessTokens = tokenProvider.Create(tokenRequest);

        var refreshToken = new RefreshToken
        {
            Id = Guid.CreateVersion7(),
            UserId = user.Id,
            Token = accessTokens.RefreshToken,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(_jwtAuthOptions.RefreshTokenExpirationDays)
        };
        // you are not removing previous refresh Tokens
        applicationDbContext.RefreshTokens.Add(refreshToken);

        await applicationDbContext.SaveChangesAsync();

        return Ok(accessTokens);
    }
    [HttpPost("refresh")]
    public async Task<ActionResult<AccessTokensDto>> Refresh(RefreshTokenDto refreshTokenDto)
    {
        RefreshToken? refreshToken = await applicationDbContext.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.Token == refreshTokenDto.RefreshToken);

        if (refreshToken is null)
        {
            return Unauthorized();
        }

        if (refreshToken.ExpiresAtUtc < DateTime.UtcNow)
        {
            return Unauthorized();
        }

        var tokenRequest = new TokenRequest(refreshToken.User.Id, refreshToken.User.Email!);
        AccessTokensDto accessTokens = tokenProvider.Create(tokenRequest);

        refreshToken.Token = accessTokens.RefreshToken;
        refreshToken.ExpiresAtUtc = DateTime.UtcNow.AddDays(_jwtAuthOptions.RefreshTokenExpirationDays);

        await applicationDbContext.SaveChangesAsync();

        return Ok(accessTokens);
    }

    [HttpGet("google/authorize")]
    public IActionResult GoogleAuthorize()
    {
        var authUrl = googleProvider.GetAuthorizationUrl();
        return Ok(new { AuthorizationUrl = authUrl });
    }

    [HttpGet("google/callback")]
    public async Task<IActionResult> GoogleCallback(string code, string state, string? error)
    {
        if (!string.IsNullOrEmpty(error))
        {
            return BadRequest($"Google authorization error: {error}");
        }

        if (string.IsNullOrEmpty(code))
        {
            return BadRequest("Authorization code is missing");
        }

        var tokens = await googleProvider.ExchangeCodeForTokens(code);

        var googleUser = await googleProvider.GetGoogleUserInfo(tokens.IdToken);

        var user = await FindOrCreateUser(googleUser);

        await googleProvider.StoreGoogleTokens(user, tokens);

        var tokenRequest = new TokenRequest(user.Id, user.Email!);
        var accessTokens = tokenProvider.Create(tokenRequest);

        var refreshToken = new RefreshToken
        {
            Id = Guid.CreateVersion7(),
            UserId = user.Id,
            Token = accessTokens.RefreshToken,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(_jwtAuthOptions.RefreshTokenExpirationDays)
        };

        applicationDbContext.RefreshTokens.Add(refreshToken);
        await applicationDbContext.SaveChangesAsync();

        var frontendUrl = $"http://localhost:5173?" +
                                $"access_token={accessTokens.AccessToken}&" +
                                $"refresh_token={accessTokens.RefreshToken}";
        return Redirect(frontendUrl);

    }





    private async Task<User> FindOrCreateUser(GoogleUserInfo googleUser)
    {
        var loginInfo = new UserLoginInfo("Google", googleUser.Id, "Google");

        var user = await userManager.FindByLoginAsync(loginInfo.LoginProvider, loginInfo.ProviderKey);

        if (user != null)
        {
            if (user.Email != googleUser.Email)
            {
                user.Email = googleUser.Email;
                user.UserName = googleUser.Email;
                await userManager.UpdateAsync(user);
            }
            return user;
        }

        user = await userManager.FindByEmailAsync(googleUser.Email);

        if (user != null)
        {
            var addLoginResult = await userManager.AddLoginAsync(user, loginInfo);
            if (!addLoginResult.Succeeded)
            {
                throw new Exception($"Failed to link Google account: {string.Join(", ", addLoginResult.Errors.Select(e => e.Description))}");
            }
            return user;
        }

        user = new User
        {
            UserName = googleUser.Email,
            Email = googleUser.Email,
            EmailConfirmed = true
        };

        var createResult = await userManager.CreateAsync(user);
        if (!createResult.Succeeded)
        {
            throw new Exception($"Failed to create user: {string.Join(", ", createResult.Errors.Select(e => e.Description))}");
        }

        var linkResult = await userManager.AddLoginAsync(user, loginInfo);
        if (!linkResult.Succeeded)
        {
            await userManager.DeleteAsync(user);
            throw new Exception($"Failed to link Google account to new user: {string.Join(", ", linkResult.Errors.Select(e => e.Description))}");
        }

        return user;
    }
}
