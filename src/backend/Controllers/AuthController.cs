using backend.DTOs;
using backend.Exceptions;
using backend.Results;
using backend.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
namespace backend.Controllers;

[ApiController]
[Route("auth")]
[AllowAnonymous]
public sealed class AuthController(IAuthService authService) : ControllerBase
{
    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterUserDto dto)
    {
        var result = await authService.RegisterAsync(dto);
        return result.IsSuccess ? Ok(result) : BadRequest(result);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginUserDto dto)
    {
        var result = await authService.LoginAsync(dto);
        return result.IsSuccess ? Ok(result) : Unauthorized(result);
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh()
    {

        var dto = new RefreshTokenDto
        {
            RefreshToken = HttpContext.Request.Cookies["refresh_token"]!
        };
        var result = await authService.RefreshTokenAsync(dto);
        return result.IsSuccess ? Ok(result) : Unauthorized(result);
    }

    [HttpGet("google/authorize")]
    public IActionResult GoogleAuthorize()
    {
        return Ok(new { AuthorizationUrl = authService.GetGoogleAuthorizationUrl() });
    }

    [HttpGet("google/callback")]
    public async Task<IActionResult> GoogleCallback(string code, string state, string? error)
    {
        try
        {
            var redirectUrl = await authService.HandleGoogleCallbackAsync(HttpContext, code, state, error);
            return Redirect(redirectUrl);
        }
        catch (AuthException ex)
        {
            return BadRequest(new AuthFailure(ex.Message));
        }
    }

    [HttpGet("me")]
    public IActionResult Test()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email = User.FindFirst(ClaimTypes.Email)?.Value;

        if (userId == null)
            return Unauthorized(new AuthFailure("User ID claim not found"));

        return Ok(new
        {
            UserId = userId,
            Email = email,
            Message = "You are authenticated"
        });
    }



    [HttpPost("logout")]
    public IActionResult Logout()
    {
        HttpContext.Response.Cookies.Delete("access_token");
        HttpContext.Response.Cookies.Delete("refresh_token");
        HttpContext.SignOutAsync();
        return Ok(new AuthSuccess(message: "Logged out successfully"));
    }
}
