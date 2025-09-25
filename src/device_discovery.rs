use anyhow::{Context, Result};
use log::{debug, info, warn};
use std::fs;
use std::path::{Path, PathBuf};

pub struct DeviceDiscovery;

impl DeviceDiscovery {
    /// Discover all video devices (cameras, webcams, capture devices)
    pub fn discover_video_devices() -> Result<Vec<PathBuf>> {
        let mut devices = Vec::new();

        // Check /dev/video* devices
        if let Ok(entries) = fs::read_dir("/dev") {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if let Some(filename) = path.file_name() {
                        let filename_str = filename.to_string_lossy();

                        // Match video devices: video0, video1, video2, etc.
                        if filename_str.starts_with("video") &&
                           filename_str.chars().skip(5).all(|c| c.is_ascii_digit()) {

                            // Verify it's actually a character device (not just a file named videoX)
                            if Self::is_video_device(&path)? {
                                devices.push(path.clone());
                                info!("Discovered video device: {}", path.display());
                            }
                        }
                    }
                }
            }
        }

        // Also check /dev/v4l/by-id/ for more descriptive names
        if let Ok(entries) = fs::read_dir("/dev/v4l/by-id") {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if Self::is_video_device(&path)? {
                        devices.push(path.clone());
                        info!("Discovered V4L device: {}", path.display());
                    }
                }
            }
        }

        // Sort for consistent ordering
        devices.sort();
        devices.dedup(); // Remove duplicates (symlinks might point to same device)

        Ok(devices)
    }

    /// Discover all audio input devices (microphones, line-in, etc.)
    pub fn discover_audio_devices() -> Result<Vec<PathBuf>> {
        let mut devices = Vec::new();

        // ALSA devices in /dev/snd/
        Self::discover_alsa_devices(&mut devices)?;

        // PulseAudio devices and sockets
        Self::discover_pulseaudio_devices(&mut devices)?;

        // JACK audio system
        Self::discover_jack_devices(&mut devices)?;

        // Sort and deduplicate
        devices.sort();
        devices.dedup();

        Ok(devices)
    }

    fn discover_alsa_devices(devices: &mut Vec<PathBuf>) -> Result<()> {
        let snd_path = Path::new("/dev/snd");
        if !snd_path.exists() {
            debug!("ALSA devices directory not found: /dev/snd");
            return Ok(());
        }

        if let Ok(entries) = fs::read_dir(snd_path) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if let Some(filename) = path.file_name() {
                        let filename_str = filename.to_string_lossy();

                        // Match PCM devices, control devices, etc.
                        if filename_str.starts_with("pcm") ||      // PCM audio devices
                           filename_str.starts_with("control") ||  // ALSA control devices
                           filename_str.starts_with("hw") ||       // Hardware devices
                           filename_str.starts_with("seq") ||      // Sequencer
                           filename_str.starts_with("timer") {     // Timer

                            if Self::is_audio_device(&path)? {
                                devices.push(path.clone());
                                info!("Discovered ALSA device: {}", path.display());
                            }
                        }
                    }
                }
            }
        }

        // Add the entire /dev/snd directory for monitoring new devices
        devices.push(snd_path.to_path_buf());

        Ok(())
    }

    fn discover_pulseaudio_devices(devices: &mut Vec<PathBuf>) -> Result<()> {
        // Common PulseAudio locations
        let pulse_paths = [
            "/tmp/.pulse",
            "/run/user/1000/pulse",  // User-specific runtime dir
            "/var/lib/pulse",
            "~/.pulse",              // Will be expanded per user
        ];

        for path_str in &pulse_paths {
            let path = Path::new(path_str);
            if path.exists() {
                devices.push(path.to_path_buf());
                info!("Discovered PulseAudio path: {}", path.display());
            }
        }

        // Check for PulseAudio sockets in runtime directories
        if let Ok(entries) = fs::read_dir("/run/user") {
            for entry in entries {
                if let Ok(entry) = entry {
                    let pulse_dir = entry.path().join("pulse");
                    if pulse_dir.exists() {
                        devices.push(pulse_dir);
                        info!("Discovered user PulseAudio: {}", entry.path().display());
                    }
                }
            }
        }

        Ok(())
    }

    fn discover_jack_devices(devices: &mut Vec<PathBuf>) -> Result<()> {
        // JACK typically uses Unix domain sockets
        let jack_paths = [
            "/dev/shm",              // JACK often uses shared memory
            "/tmp/.jack",            // JACK temporary files
            "/run/user/1000/jack",   // User JACK runtime
        ];

        for path_str in &jack_paths {
            let path = Path::new(path_str);
            if path.exists() {
                // Check if there are JACK-related files
                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries {
                        if let Ok(entry) = entry {
                            let filename = entry.file_name();
                            let filename_str = filename.to_string_lossy();

                            if filename_str.contains("jack") {
                                devices.push(entry.path());
                                info!("Discovered JACK device: {}", entry.path().display());
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if a path is actually a video device (character device with video capabilities)
    fn is_video_device(path: &Path) -> Result<bool> {
        if !path.exists() {
            return Ok(false);
        }

        // Check if it's a character device
        let metadata = fs::metadata(path)
            .with_context(|| format!("Failed to get metadata for {}", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if !metadata.file_type().is_char_device() {
                return Ok(false);
            }
        }

        // Additional check: try to identify V4L2 devices by checking /sys/class/video4linux/
        if let Some(filename) = path.file_name() {
            let filename_str = filename.to_string_lossy();
            if filename_str.starts_with("video") {
                let sys_path = format!("/sys/class/video4linux/{}", filename_str);
                return Ok(Path::new(&sys_path).exists());
            }
        }

        // If we can't determine definitively, assume it's valid if it's a char device
        Ok(true)
    }

    /// Check if a path is an audio device
    fn is_audio_device(path: &Path) -> Result<bool> {
        if !path.exists() {
            return Ok(false);
        }

        let metadata = fs::metadata(path)
            .with_context(|| format!("Failed to get metadata for {}", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            // Audio devices can be character devices, directories, or sockets
            Ok(metadata.file_type().is_char_device() ||
               metadata.file_type().is_dir() ||
               metadata.file_type().is_socket())
        }

        #[cfg(not(unix))]
        Ok(true)
    }

    /// Discover devices dynamically and return paths that should be monitored
    pub fn discover_all_monitored_paths() -> Result<Vec<PathBuf>> {
        let mut paths = Vec::new();

        // Add video devices
        match Self::discover_video_devices() {
            Ok(video_devices) => {
                paths.extend(video_devices);
                info!("Discovered {} video devices", paths.len());
            }
            Err(e) => {
                warn!("Failed to discover video devices: {}", e);
            }
        }

        // Add audio devices
        match Self::discover_audio_devices() {
            Ok(audio_devices) => {
                let audio_count = audio_devices.len();
                paths.extend(audio_devices);
                info!("Discovered {} audio devices", audio_count);
            }
            Err(e) => {
                warn!("Failed to discover audio devices: {}", e);
            }
        }

        Ok(paths)
    }

    /// Check if new devices have appeared (for periodic rescanning)
    pub fn rescan_devices(current_devices: &[PathBuf]) -> Result<Vec<PathBuf>> {
        let discovered = Self::discover_all_monitored_paths()?;

        let mut new_devices = Vec::new();
        for device in discovered {
            if !current_devices.contains(&device) {
                new_devices.push(device);
            }
        }

        if !new_devices.is_empty() {
            info!("Discovered {} new devices", new_devices.len());
        }

        Ok(new_devices)
    }
}