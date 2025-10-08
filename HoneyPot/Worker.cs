using System.Net;
using System.Net.Sockets;
using System.Text;

namespace HoneyPot;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private TcpListener listener;
    public Worker(ILogger<Worker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (listener == null)
        {
            throw new InvalidOperationException("Listener was not initialized.");
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var client = await listener.AcceptTcpClientAsync(stoppingToken);
                _ = HandleConnectionAsync(client, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Error accepting connection.");
            }
        }
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogInformation("Attempting to download Sysmon configuration...");
            using (var client = new HttpClient())
            {
                using (var stream = await client.GetStreamAsync("https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/1836897f12fbd6a0a473665ef6abc34a6b497e31/sysmonconfig-export.xml"))
                {
                    using (var fs = new FileStream("sysmonconfig-export.xml", FileMode.Create))
                    {
                        await stream.CopyToAsync(fs, cancellationToken);
                    }
                }
            }
            _logger.LogInformation("Applying Sysmon configuration...");

            var startInfo = new System.Diagnostics.ProcessStartInfo
            {
                WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
                FileName = "cmd.exe",
                Arguments = "/C sysmon64 -accepteula -i sysmonconfig-export.xml",

            };

            var process = System.Diagnostics.Process.Start(startInfo);
            if (process != null)
            {
                await process.WaitForExitAsync(cancellationToken);
                if (process.ExitCode == 0)
                {
                    _logger.LogInformation("Sysmon configuration applied successfully.");
                }
                else
                {
                    _logger.LogWarning("Sysmon process exited with code {ExitCode}", process.ExitCode);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to download or apply Sysmon configuration!");
        }


        listener = new TcpListener(IPAddress.Any, 8080);
        listener.Start();
        _logger.LogInformation("Honey Pot started listening on port 8080 at: {time}", DateTimeOffset.Now);


        await base.StartAsync(cancellationToken);

    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        listener?.Stop();
        _logger.LogInformation("Honeypot stopped listening at: {time}", DateTimeOffset.Now);
        return base.StopAsync(cancellationToken);
    }

    private async Task HandleConnectionAsync(TcpClient client, CancellationToken token)
    {
        var endpoint = client.Client.RemoteEndPoint?.ToString() ?? "Unknown";
        _logger.LogInformation("Connection received from {Endpoint}", endpoint);

        try
        {
            using NetworkStream stream = client.GetStream();
            stream.ReadTimeout = 2000;
            stream.WriteTimeout = 2000;

            byte[] buffer = new byte[1024];
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, token);

            if (bytesRead > 0)
            {
                string request = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                if (IsHttpRequest(request))
                {
                    _logger.LogWarning("Detected a potentional HTTP Request from {Endpoint}. Data:\n{Request}", endpoint, request.Trim());
                    await SendFakeHttpResponseAsync(stream, token);
                }
                else if (IsSshHandshake(request))
                {
                    _logger.LogWarning("Detected a potentional SSH Handshake attempt from {Endpoint}. Data:\n{Data}", endpoint, request.Trim());
                    await SendBannerAsync(stream, "SSH-2.0-OpenSSH_7.4\r\n", token);
                }
                else if (IsNmapProbe(request))
                {
                    _logger.LogWarning("Detected a potential Nmap probe from {Endpoint}. Data:\n{Data}", endpoint, request.Trim().Replace("\r", "\\r").Replace("\n", "\\n"));
                }
                else
                {
                    _logger.LogInformation("Could not fingerprint connection from {Endpoint}. Data:\n{Data}", endpoint, request.Trim().Replace("\r", "\\r").Replace("\n", "\\n"));
                    await SendBannerAsync(stream, "Access Denied.\r\n", token);
                }
            }
            else
            {
                _logger.LogWarning("Received empty request from {Endpoint}. Likely a port scan.", endpoint);
            }
        }
        catch (IOException ex) when (ex.InnerException is SocketException)
        {
            _logger.LogInformation("Connection from {Endpoint} closed by the client.", endpoint);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling connection from {Endpoint}", endpoint);
        }
        finally
        {
            client.Close();
            _logger.LogInformation("Connection from {Endpoint} closed", endpoint);
        }
    }
        private bool IsHttpRequest(string r) => 
        r.StartsWith("GET ") || r.StartsWith("POST ") || r.StartsWith("HEAD ") || r.StartsWith("PUT ") || r.StartsWith("OPTIONS ");

    private bool IsSshHandshake(string r) => r.StartsWith("SSH-2.0-");
    
    private bool IsNmapProbe(string r) => 
        r.Contains("nmap", StringComparison.OrdinalIgnoreCase) || r.Trim() == "GET / HTTP/1.0\r\n\r\n";

    private async Task SendBannerAsync(NetworkStream stream, string banner, CancellationToken token)
    {
        byte[] bannerBytes = Encoding.UTF8.GetBytes(banner);
        await stream.WriteAsync(bannerBytes, 0, bannerBytes.Length, token);
    }
    
    private async Task SendFakeHttpResponseAsync(NetworkStream stream, CancellationToken token)
    {
        string responseBody = "<html><head><title>Welcome</title></head><body><h1>Access Forbidden</h1><p>You do not have permission to access this server.</p></body></html>";
        string httpResponse = "HTTP/1.1 403 Forbidden\r\n" +
                              "Content-Type: text/html; charset=UTF-8\r\n" +
                              $"Content-Length: {responseBody.Length}\r\n" +
                              "Server: Apache/2.4.29 (Ubuntu)\r\n" +
                              "Connection: close\r\n\r\n" +
                              responseBody;

        byte[] responseBytes = Encoding.UTF8.GetBytes(httpResponse);
        await stream.WriteAsync(responseBytes, 0, responseBytes.Length, token);
    }
}
