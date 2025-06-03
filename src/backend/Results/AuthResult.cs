using backend.DTOs;
using System.Text.Json.Serialization;

namespace backend.Results;

public abstract class AuthResult
{
    public bool IsSuccess { get; }

    protected AuthResult(bool isSuccess)
    {
        IsSuccess = isSuccess;
    }
}


public sealed class AuthSuccess : AuthResult
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AccessTokensDto? Tokens { get; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Message { get; }

    public AuthSuccess(AccessTokensDto? tokens = null, string? message = null)
        : base(true)
    {
        Tokens = tokens;
        Message = message;
    }
}
public sealed class AuthFailure : AuthResult
{
    public string Error { get; }

    public AuthFailure(string error) : base(false)
    {
        Error = error;
    }
}
