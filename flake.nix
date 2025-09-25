{
  description = "Security Monitor Daemon - Linux filesystem and hardware security monitoring";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rustfmt" "clippy" ];
        };

        secmon-daemon = pkgs.rustPlatform.buildRustPackage {
          pname = "secmon-daemon";
          version = "0.1.0";

          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = with pkgs; [
            pkg-config
            rustToolchain
          ];

          buildInputs = with pkgs; [
            systemd
            udev
            alsa-lib
          ] ++ lib.optionals stdenv.isDarwin [
            darwin.apple_sdk.frameworks.Security
            darwin.apple_sdk.frameworks.SystemConfiguration
          ];

          # Required for udev access
          postInstall = ''
            mkdir -p $out/lib/udev/rules.d
            cat > $out/lib/udev/rules.d/99-secmon.rules << EOF
            # Allow secmon-daemon to access USB devices
            SUBSYSTEM=="usb", GROUP="secmon", MODE="0664"
            EOF
          '';

          meta = with pkgs.lib; {
            description = "Security monitoring daemon for Linux filesystem and hardware events";
            homepage = "https://github.com/your-username/secmon-daemon";
            license = licenses.mit;
            maintainers = [ maintainers.yourname ];
            platforms = platforms.linux;
          };
        };

      in
      {
        packages.default = secmon-daemon;
        packages.secmon-daemon = secmon-daemon;

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            pkg-config
            systemd
            udev
            alsa-lib
            # Development tools
            rust-analyzer
            cargo-watch
            cargo-edit
          ];

          shellHook = ''
            echo "🦀 Rust development environment for secmon-daemon"
            echo "📦 Available commands:"
            echo "  cargo build --release  # Build the daemon"
            echo "  cargo run -- config.toml  # Run with config"
            echo "  cargo test             # Run tests"
          '';
        };

        # NixOS module
        nixosModules.default = { config, lib, pkgs, ... }:
          let
            cfg = config.services.secmon;
            settingsFormat = pkgs.formats.toml { };
            configFile = settingsFormat.generate "secmon-config.toml" cfg.settings;
          in
          {
            options.services.secmon = {
              enable = lib.mkEnableOption "secmon security monitoring daemon";

              package = lib.mkOption {
                type = lib.types.package;
                default = secmon-daemon;
                description = "The secmon-daemon package to use";
              };

              settings = lib.mkOption {
                type = settingsFormat.type;
                default = {};
                description = ''
                  Configuration for secmon-daemon.
                  See the default configuration for available options.
                '';
                example = lib.literalExpression ''
                  {
                    socket_path = "/run/secmon/secmon.sock";
                    log_level = "info";
                    watches = [
                      {
                        path = "/dev/video0";
                        description = "Primary camera";
                        enabled = true;
                        recursive = false;
                      }
                      {
                        path = "/home";
                        description = "SSH key monitoring";
                        enabled = true;
                        recursive = true;
                      }
                    ];
                  }
                '';
              };

              user = lib.mkOption {
                type = lib.types.str;
                default = "secmon";
                description = "User to run secmon-daemon as";
              };

              group = lib.mkOption {
                type = lib.types.str;
                default = "secmon";
                description = "Group to run secmon-daemon as";
              };

              socketPath = lib.mkOption {
                type = lib.types.str;
                default = "/run/secmon/secmon.sock";
                description = "Path for the Unix domain socket";
              };

              extraGroups = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ "audio" "video" ];
                description = "Additional groups for the secmon user";
              };

              monitors = {
                filesystem = lib.mkEnableOption "filesystem monitoring" // { default = true; };
                network = lib.mkEnableOption "network connection monitoring" // { default = true; };
                usb = lib.mkEnableOption "USB device monitoring" // { default = true; };
                camera = lib.mkEnableOption "camera access monitoring" // { default = true; };
                microphone = lib.mkEnableOption "microphone access monitoring" // { default = true; };
                ssh = lib.mkEnableOption "SSH security monitoring" // { default = true; };
              };

              watches = lib.mkOption {
                type = lib.types.listOf (lib.types.submodule {
                  options = {
                    path = lib.mkOption {
                      type = lib.types.str;
                      description = "Path to monitor";
                    };
                    description = lib.mkOption {
                      type = lib.types.str;
                      description = "Description of what this path monitors";
                    };
                    enabled = lib.mkOption {
                      type = lib.types.bool;
                      default = true;
                      description = "Whether this watch is enabled";
                    };
                    recursive = lib.mkOption {
                      type = lib.types.bool;
                      default = false;
                      description = "Whether to monitor subdirectories";
                    };
                    pattern = lib.mkOption {
                      type = lib.types.bool;
                      default = false;
                      description = "Whether to treat path as a glob pattern";
                    };
                    auto_discover = lib.mkOption {
                      type = lib.types.bool;
                      default = false;
                      description = "Whether to automatically discover devices";
                    };
                  };
                });
                default = [];
                description = "Additional filesystem paths to monitor (supports glob patterns and auto-discovery)";
              };
            };

            config = lib.mkIf cfg.enable {
              # Merge user settings with defaults
              services.secmon.settings = lib.mkDefault {
                socket_path = cfg.socketPath;
                log_level = "info";
                watches =
                  lib.optionals cfg.monitors.camera [
                    { path = "/dev/video*"; description = "All camera/video devices (auto-discovered)"; enabled = true; recursive = false; pattern = true; auto_discover = true; }
                  ] ++
                  lib.optionals cfg.monitors.microphone [
                    { path = "/dev/snd/*"; description = "All ALSA audio devices (auto-discovered)"; enabled = true; recursive = true; pattern = true; auto_discover = true; }
                    { path = "/tmp/.pulse*"; description = "PulseAudio devices (auto-discovered)"; enabled = true; recursive = true; pattern = true; auto_discover = true; }
                    { path = "/run/user/*/pulse"; description = "User PulseAudio runtime directories"; enabled = true; recursive = true; pattern = true; auto_discover = true; }
                  ] ++
                  lib.optionals cfg.monitors.ssh [
                    { path = "/home"; description = "Home directories for SSH keys"; enabled = true; recursive = true; pattern = false; auto_discover = false; }
                    { path = "/etc/ssh"; description = "SSH daemon configuration"; enabled = true; recursive = true; pattern = false; auto_discover = false; }
                    { path = "/var/log/auth.log"; description = "SSH authentication logs"; enabled = true; recursive = false; pattern = false; auto_discover = false; }
                  ] ++
                  cfg.watches;
              };

              # Create user and group
              users.users.${cfg.user} = {
                group = cfg.group;
                isSystemUser = true;
                description = "Secmon daemon user";
                extraGroups = cfg.extraGroups;
              };

              users.groups.${cfg.group} = {};

              # Create runtime directory
              systemd.tmpfiles.rules = [
                "d /run/secmon 0755 ${cfg.user} ${cfg.group} -"
              ];

              # Install udev rules
              services.udev.packages = [ cfg.package ];

              # Systemd service
              systemd.services.secmon = {
                description = "Security Monitor Daemon";
                documentation = [ "https://github.com/your-username/secmon-daemon" ];
                after = [ "network.target" "systemd-udev-settle.service" ];
                wants = [ "network.target" ];
                wantedBy = [ "multi-user.target" ];

                serviceConfig = {
                  Type = "simple";
                  User = cfg.user;
                  Group = cfg.group;
                  ExecStart = "${cfg.package}/bin/secmon-daemon ${configFile}";
                  Restart = "always";
                  RestartSec = "5";

                  # Security settings
                  NoNewPrivileges = true;
                  PrivateTmp = true;
                  ProtectSystem = "strict";
                  ProtectHome = "read-only";
                  ReadWritePaths = [ "/run/secmon" "/var/log" ];

                  # Capabilities for device access
                  CapabilityBoundingSet = [ "CAP_DAC_READ_SEARCH" ];
                  AmbientCapabilities = [ "CAP_DAC_READ_SEARCH" ];

                  # Environment
                  Environment = [
                    "RUST_LOG=info"
                    "RUST_BACKTRACE=1"
                  ];

                  # Logging
                  StandardOutput = "journal";
                  StandardError = "journal";
                  SyslogIdentifier = "secmon-daemon";

                  # Process management
                  KillMode = "mixed";
                  KillSignal = "SIGTERM";
                  TimeoutStopSec = "30";
                };

                # Enable if monitors require it
                unitConfig = lib.mkIf cfg.monitors.usb {
                  After = lib.mkAfter [ "systemd-udev-settle.service" ];
                };
              };

              # Optional: Install secmon-client globally
              environment.systemPackages = [ cfg.package ];
            };
          };
      });
}