export default function App() {
  const handleGoogleLogin = async () => {
    const response = await fetch("http://localhost:5000/auth/google/authorize");
    const data = await response.json();
    window.location.href = data.authorizationUrl;
  };

  return (
    <div>
      <button onClick={handleGoogleLogin} className="cursor-pointer bg-accent">
        Sign in with Google
      </button>
    </div>
  );
}
