using backend.DTOs;

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
    public AccessTokensDto Tokens { get; }

    public AuthSuccess(AccessTokensDto tokens) : base(true)
    {
        Tokens = tokens;
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
