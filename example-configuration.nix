# Example NixOS configuration using secmon-daemon
{
  description = "Example NixOS system with secmon security monitoring";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    secmon.url = "github:your-username/secmon-daemon";
  };

  outputs = { nixpkgs, secmon, ... }: {
    nixosConfigurations.example = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        # Import the secmon module
        secmon.nixosModules.default

        {
          # Enable the secmon service
          services.secmon = {
            enable = true;

            # Optional: Override package
            # package = secmon.packages.x86_64-linux.default;

            # Configure which monitoring features to enable
            monitors = {
              filesystem = true;     # Monitor filesystem events (inotify)
              network = true;        # Monitor network connections
              usb = true;           # Monitor USB device insertions
              camera = true;        # Monitor camera device access
              microphone = true;    # Monitor microphone access
              ssh = true;           # Monitor SSH-related security
            };

            # Override socket path if needed
            socketPath = "/run/secmon/secmon.sock";

            # Add custom filesystem watches
            watches = [
              {
                path = "/etc/nixos";
                description = "NixOS configuration files";
                enabled = true;
                recursive = true;
              }
              {
                path = "/root/.ssh";
                description = "Root SSH keys";
                enabled = true;
                recursive = true;
              }
              {
                path = "/var/lib/secrets";
                description = "Application secrets";
                enabled = true;
                recursive = false;
              }
            ];

            # Fine-tune configuration
            settings = {
              socket_path = "/run/secmon/secmon.sock";
              log_level = "info";

              # The watches array is automatically generated from monitors + watches options
              # But you can override the entire configuration here if needed:
              # watches = [
              #   {
              #     path = "/custom/path";
              #     description = "Custom monitoring";
              #     enabled = true;
              #     recursive = false;
              #   }
              # ];
            };

            # Security: run as dedicated user
            user = "secmon";
            group = "secmon";
            extraGroups = [ "audio" "video" "input" ]; # Needed for device access
          };

          # Optional: Install the client globally for easy access
          environment.systemPackages = [
            secmon.packages.x86_64-linux.default
          ];

          # Example: Configure a monitoring client service that sends alerts
          systemd.services.secmon-alerting = {
            description = "Secmon Alert Handler";
            after = [ "secmon.service" ];
            wants = [ "secmon.service" ];
            wantedBy = [ "multi-user.target" ];

            serviceConfig = {
              Type = "simple";
              User = "nobody";
              Group = "nogroup";
              Restart = "always";
              RestartSec = "10";
            };

            script = ''
              # Connect to secmon and process alerts
              ${secmon.packages.x86_64-linux.default}/bin/secmon-client /run/secmon/secmon.sock 2>&1 | while IFS= read -r line; do
                # Log all events
                echo "$(date): $line" >> /var/log/secmon-alerts.log

                # Send critical alerts via your preferred method
                if echo "$line" | grep -q "CRITICAL"; then
                  # Example: send to webhook, email, SMS, etc.
                  curl -X POST "https://your-webhook.com/alerts" \
                    -H "Content-Type: application/json" \
                    -d "{\"alert\": \"$line\", \"timestamp\": \"$(date -Iseconds)\"}" || true
                fi
              done
            '';
          };

          # Example firewall configuration if needed
          # networking.firewall.allowedTCPPorts = [ ];

          # Enable essential services
          services.openssh.enable = true;

          # Example: Create a service that monitors the secmon socket
          systemd.services.secmon-status = {
            description = "Secmon Status Monitor";
            serviceConfig = {
              Type = "oneshot";
            };
            script = ''
              if [ -S /run/secmon/secmon.sock ]; then
                echo "Secmon daemon is running and socket is available"
              else
                echo "ERROR: Secmon socket not found!"
                exit 1
              fi
            '';
          };

          # Timer to periodically check secmon status
          systemd.timers.secmon-status = {
            wantedBy = [ "timers.target" ];
            partOf = [ "secmon-status.service" ];
            timerConfig = {
              OnCalendar = "*:0/5";  # Every 5 minutes
              Unit = "secmon-status.service";
            };
          };
        }
      ];
    };
  };
}

# Alternative: Simpler configuration
{
  # Minimal configuration - just enable with defaults
  services.secmon.enable = true;
}

# Or: Configuration with custom settings
{
  services.secmon = {
    enable = true;

    # Disable some monitors if not needed
    monitors = {
      filesystem = true;
      network = true;
      usb = true;
      camera = true;
      microphone = false;  # Disable if no microphone monitoring needed
      ssh = true;
    };

    # Add custom paths
    watches = [
      {
        path = "/etc/shadow";
        description = "System password file";
        enabled = true;
        recursive = false;
      }
    ];

    # Custom settings
    settings = {
      log_level = "debug";  # More verbose logging
      socket_path = "/tmp/secmon.sock";  # Different socket location
    };
  };
}