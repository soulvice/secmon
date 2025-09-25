use anyhow::{Context, Result};
use libudev::{Context as UdevContext, Device, Enumerator, Event, Monitor};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::broadcast;
use chrono::Utc;

use crate::{EventType, SecurityEvent, EventDetails, Severity};

pub struct UsbMonitor {
    event_sender: broadcast::Sender<SecurityEvent>,
    context: UdevContext,
}

impl UsbMonitor {
    pub fn new(event_sender: broadcast::Sender<SecurityEvent>) -> Result<Self> {
        let context = UdevContext::new()
            .context("Failed to create udev context")?;

        Ok(Self {
            event_sender,
            context,
        })
    }

    pub async fn start_monitoring(&mut self) -> Result<()> {
        let mut monitor = match Monitor::new(&self.context) {
            Ok(monitor) => monitor,
            Err(e) => {
                warn!("USB monitoring disabled - failed to create monitor: {} (may require root permissions)", e);
                return Ok(());
            }
        };

        if let Err(e) = monitor.match_subsystem("usb") {
            warn!("USB monitoring disabled - failed to match USB subsystem: {}", e);
            return Ok(());
        }

        info!("USB monitoring started");

        // Try to get the socket and monitor events
        let mut socket = match monitor.listen() {
            Ok(socket) => socket,
            Err(e) => {
                warn!("USB monitoring disabled - failed to listen on udev socket: {} (requires root or udev group membership)", e);
                return Ok(());
            }
        };

        debug!("USB monitor socket created successfully");

        // Monitor USB events
        loop {
            match socket.receive_event() {
                Some(event) => {
                    debug!("Received USB event");
                    self.handle_usb_event(event).await;
                }
                None => {
                    // No event available right now, continue polling
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }

        info!("USB monitoring stopped");
        Ok(())
    }

    async fn handle_usb_event(&self, event: Event) {
        let device = event.device();
        let action = event.event_type();

        debug!("USB event: {:?} for device: {:?}", action, device.syspath());

        match action {
            libudev::EventType::Add => {
                self.emit_usb_insertion_event(&device).await;
            }
            libudev::EventType::Remove => {
                self.emit_usb_removal_event(&device).await;
            }
            _ => {
                // Ignore bind/unbind/change events for now
                debug!("Ignored USB event type: {:?}", action);
            }
        }
    }

    async fn emit_usb_insertion_event(&self, device: &Device) {
        let mut metadata = HashMap::new();

        // Extract device information
        if let Some(devtype) = device.devtype() {
            metadata.insert("device_type".to_string(), devtype.to_string_lossy().to_string());
        }

        if let Some(vendor_id) = device.property_value("ID_VENDOR_ID") {
            metadata.insert("vendor_id".to_string(), vendor_id.to_string_lossy().to_string());
        }

        if let Some(product_id) = device.property_value("ID_PRODUCT_ID") {
            metadata.insert("product_id".to_string(), product_id.to_string_lossy().to_string());
        }

        if let Some(vendor) = device.property_value("ID_VENDOR") {
            metadata.insert("vendor".to_string(), vendor.to_string_lossy().to_string());
        }

        if let Some(product) = device.property_value("ID_MODEL") {
            metadata.insert("product".to_string(), product.to_string_lossy().to_string());
        }

        if let Some(serial) = device.property_value("ID_SERIAL_SHORT") {
            metadata.insert("serial".to_string(), serial.to_string_lossy().to_string());
        }

        if let Some(devpath) = device.devnode() {
            metadata.insert("device_path".to_string(), devpath.to_string_lossy().to_string());
        }

        let severity = self.classify_usb_device_severity(&metadata);

        let description = if let (Some(vendor), Some(product)) = (
            metadata.get("vendor"),
            metadata.get("product")
        ) {
            format!("USB device inserted: {} {} ({}:{})",
                vendor, product,
                metadata.get("vendor_id").unwrap_or(&"unknown".to_string()),
                metadata.get("product_id").unwrap_or(&"unknown".to_string())
            )
        } else {
            format!("USB device inserted: {}:{}",
                metadata.get("vendor_id").unwrap_or(&"unknown".to_string()),
                metadata.get("product_id").unwrap_or(&"unknown".to_string())
            )
        };

        let event = SecurityEvent {
            timestamp: Utc::now(),
            event_type: EventType::UsbDeviceInserted,
            path: device.syspath().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/sys/devices/usb")),
            details: EventDetails {
                severity,
                description,
                metadata,
            },
        };

        if let Err(e) = self.event_sender.send(event) {
            error!("Failed to send USB insertion event: {}", e);
        }
    }

    async fn emit_usb_removal_event(&self, device: &Device) {
        let mut metadata = HashMap::new();

        if let Some(devtype) = device.devtype() {
            metadata.insert("device_type".to_string(), devtype.to_string_lossy().to_string());
        }

        let event = SecurityEvent {
            timestamp: Utc::now(),
            event_type: EventType::UsbDeviceInserted, // We could add UsbDeviceRemoved if needed
            path: device.syspath().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/sys/devices/usb")),
            details: EventDetails {
                severity: Severity::Low,
                description: "USB device removed".to_string(),
                metadata,
            },
        };

        if let Err(e) = self.event_sender.send(event) {
            error!("Failed to send USB removal event: {}", e);
        }
    }

    fn classify_usb_device_severity(&self, metadata: &HashMap<String, String>) -> Severity {
        // Check for potentially dangerous device types
        if let Some(device_type) = metadata.get("device_type") {
            match device_type.as_str() {
                "usb_device" => {
                    // Check vendor/product IDs for known devices
                    if let (Some(vendor_id), Some(product_id)) = (
                        metadata.get("vendor_id"),
                        metadata.get("product_id")
                    ) {
                        // Known suspicious devices or patterns
                        match (vendor_id.as_str(), product_id.as_str()) {
                            // Rubber Ducky-like devices (some common HID attack devices)
                            ("f000", _) | ("dead", _) => Severity::Critical,
                            // Mass storage devices get medium severity for data exfiltration risk
                            _ if self.is_mass_storage_device(metadata) => Severity::Medium,
                            // HID devices (keyboards, mice) can be used for attacks
                            _ if self.is_hid_device(metadata) => Severity::High,
                            _ => Severity::Low,
                        }
                    } else {
                        Severity::Medium
                    }
                }
                _ => Severity::Low,
            }
        } else {
            Severity::Low
        }
    }

    fn is_mass_storage_device(&self, metadata: &HashMap<String, String>) -> bool {
        // Check if it's a mass storage device
        metadata.values().any(|v| {
            let v_lower = v.to_lowercase();
            v_lower.contains("mass_storage") ||
            v_lower.contains("storage") ||
            v_lower.contains("disk")
        })
    }

    fn is_hid_device(&self, metadata: &HashMap<String, String>) -> bool {
        // Check if it's a Human Interface Device
        metadata.values().any(|v| {
            let v_lower = v.to_lowercase();
            v_lower.contains("hid") ||
            v_lower.contains("keyboard") ||
            v_lower.contains("mouse")
        })
    }
}