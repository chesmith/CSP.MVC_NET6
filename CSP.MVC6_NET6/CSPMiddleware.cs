using System.Security.Cryptography;
using System.Text;

namespace CSP.MVC_NET6
{
    public class CSPMiddleware
    {
        private readonly RequestDelegate _next;

        public CSPMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            string nonce = GenerateNonce();
            //string policy = $"default-src 'self' 'nonce-{nonce}'; script-src-attr 'unsafe-inline'; connect-src  wss://localhost:*";
			string policy = $"default-src 'self'; " +
				$"script-src 'self' 'unsafe-eval'; " +
				$"script-src-elem 'self' 'nonce-{nonce}' www.scripthost.com; " +
				$"script-src-attr 'unsafe-inline'; " +
				$"style-src 'self'; " +
				$"style-src-elem 'self' 'nonce-{nonce}' www.stylehost.com; " +
				$"style-src-attr 'unsafe-inline'; " +
				$"object-src 'none'; " +
				$"frame-ancestors 'self'; " +
				$"frame-src 'self';" +
                $"connect-src wss://localhost:*;";

			context.Response.Headers.Add("Content-Security-Policy", policy);

            // You can also add other security headers if needed, like X-Content-Type-Options, X-Frame-Options, etc.

            // Intercept the response body stream
            Stream originalBody = context.Response.Body;
            using (var newBody = new MemoryStream())
            {
                context.Response.Body = newBody;

                await _next(context);

                // Rewind the stream for reading
                newBody.Seek(0, SeekOrigin.Begin);
                string responseBody = new StreamReader(newBody).ReadToEnd();

                // Replace '{nonce}' with the actual nonce
                responseBody = responseBody.Replace("{nonce}", nonce);

                // Write the modified content back to the response
                await originalBody.WriteAsync(System.Text.Encoding.UTF8.GetBytes(responseBody), 0, responseBody.Length);
            }
        }

        private string GenerateNonce()
        {
            var nonceBytes = new byte[32];
            var generator = RandomNumberGenerator.Create();
            generator.GetBytes(nonceBytes);
            return Convert.ToBase64String(nonceBytes);
        }
    }
}
