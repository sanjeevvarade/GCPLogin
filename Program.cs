using FirebaseAdmin;
using FirebaseAdmin.Auth;
using Google.Apis.Auth.OAuth2;

namespace GcpSocialLoginDemo
{
    public record TokenRequest(string Token);

    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            FirebaseApp.Create(new AppOptions
            {
                Credential = GoogleCredential.FromFile("service-account.json")
            });

            var app = builder.Build();

            app.UseDefaultFiles();
            app.UseStaticFiles();

            app.MapPost("/auth/verify", async (TokenRequest request) =>
            {
                try
                {
                    FirebaseToken decoded = await FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(request.Token);
                    UserRecord user = await FirebaseAuth.DefaultInstance.GetUserAsync(decoded.Uid);

                    return Results.Ok(new
                    {
                        message = "User authenticated",
                        uid = user.Uid,
                        email = user.Email,
                        providers = user.ProviderData.Select(p => new { p.ProviderId, p.Email })
                    });
                }
                catch
                {
                    return Results.Unauthorized();
                }
            });

            app.MapGet("/secure", async (HttpRequest req) =>
            {
                var authHeader = req.Headers.Authorization.ToString();
                if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer "))
                    return Results.Unauthorized();

                var token = authHeader["Bearer ".Length..];

                try
                {
                    var decoded = await FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(token);
                    return Results.Ok(new { message = "Secure endpoint accessed", uid = decoded.Uid });
                }
                catch
                {
                    return Results.Unauthorized();
                }
            });

            app.Run();
        }
    }
}