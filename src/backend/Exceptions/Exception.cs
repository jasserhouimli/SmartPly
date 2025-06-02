namespace backend.Exceptions;

public class AuthException : Exception
{
    public AuthException(string message) : base(message) { }
}

public class InvalidCredentialsException : AuthException
{
    public InvalidCredentialsException() : base("Invalid credentials.") { }
}

public class TokenExpiredException : AuthException
{
    public TokenExpiredException() : base("Refresh token expired.") { }
}

public class TokenInvalidException : AuthException
{
    public TokenInvalidException() : base("Refresh token invalid.") { }
}

public class UserCreationException : AuthException
{
    public UserCreationException(string details) : base($"User creation failed: {details}") { }
}

public class UserLinkingException : AuthException
{
    public UserLinkingException(string details) : base($"User linking failed: {details}") { }
}
