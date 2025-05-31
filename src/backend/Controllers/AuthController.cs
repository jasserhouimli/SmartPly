using backend.DTOs;
using backend.Entities;
using backend.Services;
using backend.Settings;
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
    IOptions<JwtAuthOptions> options) : ControllerBase
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
}