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
                // Wait for an incoming connection
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
            if(process.ExitCode == 0)
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

            using NetworkStream stream = client.GetStream();

            string banner = "SSH-2.0-OpenSSH_for_Windows_8.6\r\n";
            byte[] bannerBytes = Encoding.UTF8.GetBytes(banner);
            await stream.WriteAsync(bannerBytes, 0, bannerBytes.Length, token);

            await Task.Delay(500, token);

            byte[] buffer = new byte[1024];
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, token);
            if (bytesRead > 0)
            {
                string input = Encoding.UTF8.GetString(buffer, 0, bytesRead).Trim();
                _logger.LogInformation("Received input: \"{Input}\" from {Endpoint}", input, endpoint);
            }

            
            string response = "Access denied.\r\n";
            byte[] responseBytes = Encoding.UTF8.GetBytes(response);
            await stream.WriteAsync(responseBytes, 0, responseBytes.Length, token);

            client.Close();
            _logger.LogInformation("Connection from {Endpoint} closed", endpoint);
        }
}
