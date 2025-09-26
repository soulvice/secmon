# GitHub Actions Setup for Cachix Integration

This document explains how to set up the required secrets for the GitHub Actions workflow to build and cache the secmon-daemon project.

## Required Secrets

You need to configure the following secrets in your GitHub repository:

### 1. CACHIX_AUTH_TOKEN

This is your Cachix authentication token that allows the workflow to push build artifacts to your Cachix cache.

#### How to get your Cachix auth token:

1. **Create a Cachix account** (if you don't have one):
   ```bash
   # Install cachix if not already installed
   nix-env -iA cachix -f https://cachix.org/api/v1/install

   # Login to Cachix (this will open a browser for authentication)
   cachix authtoken
   ```

2. **Create a cache** (if you don't have one):
   ```bash
   # Create a new cache named 'secmon-daemon' (or choose your own name)
   cachix create secmon-daemon
   ```

3. **Get your auth token**:
   ```bash
   # This will display your auth token
   cachix authtoken
   ```

4. **Alternative method** - Get token from Cachix web interface:
   - Go to https://app.cachix.org/
   - Login to your account
   - Go to "Personal Auth Tokens" in your profile
   - Create a new token or copy an existing one

#### How to add the secret to GitHub:

1. Go to your GitHub repository
2. Click on **Settings** tab
3. In the left sidebar, click **Secrets and variables** → **Actions**
4. Click **New repository secret**
5. Name: `CACHIX_AUTH_TOKEN`
6. Value: Paste your Cachix auth token
7. Click **Add secret**

### 2. Cache Name Configuration

The workflow is currently configured to use a cache named `secmon-daemon`. If you want to use a different cache name:

1. Change the cache name in `.github/workflows/rust.yml`:
   ```yaml
   - name: Setup Cachix
     uses: cachix/cachix-action@v12
     with:
       name: your-cache-name-here  # Change this line
       authToken: '${{ secrets.CACHIX_AUTH_TOKEN }}'
   ```

## Workflow Features

The updated workflow provides:

### Main Build Job:
- ✅ **Nix-based building** - Uses your flake.nix for reproducible builds
- ✅ **Cachix integration** - Automatically pushes build artifacts to cache
- ✅ **Flake validation** - Runs `nix flake check` to ensure your flake is valid
- ✅ **Multi-binary support** - Builds all three binaries (daemon, client, msg)
- ✅ **Test execution** - Runs cargo tests in Nix environment
- ✅ **Artifact upload** - Uploads binaries as GitHub artifacts

### Cross-Platform Build Job:
- ✅ **Multi-architecture** - Builds for x86_64-linux and aarch64-linux
- ✅ **Cache sharing** - Shares cache between different architectures
- ✅ **Optional execution** - Only runs on push to main branch

## What the Workflow Does

1. **On every push/PR**:
   - Checks out your code
   - Sets up Nix with flakes enabled
   - Configures Cachix with your auth token
   - Validates your flake configuration
   - Builds all packages using Nix
   - Runs tests in the Nix development environment
   - **Automatically uploads all build artifacts to Cachix**

2. **On push to main**:
   - Additionally runs cross-platform builds
   - Uploads binary artifacts to GitHub

## Benefits

- **Faster builds** - Dependencies are cached and shared across builds
- **Reproducible builds** - Nix ensures consistent build environment
- **Cross-platform support** - Easily build for multiple architectures
- **Public cache** - Other users can benefit from your cached builds
- **Zero manual cache management** - Everything is automated

## Testing the Setup

After adding the secrets, push a commit to trigger the workflow. You can monitor:

1. **GitHub Actions tab** - See build progress and logs
2. **Your Cachix cache** - Visit https://app.cachix.org/cache/your-cache-name to see uploaded artifacts
3. **Build artifacts** - Download binaries from the GitHub Actions "Artifacts" section

## Troubleshooting

### Authentication Issues
- Verify `CACHIX_AUTH_TOKEN` is correctly set in GitHub secrets
- Ensure the token has write permissions to your cache
- Check that the cache name in the workflow matches your actual cache

### Build Failures
- Check `nix flake check` passes locally
- Ensure all dependencies are properly declared in flake.nix
- Verify Cargo.lock is up to date

### Cache Issues
- Make sure your Cachix cache exists and is accessible
- Check cache permissions (public caches work better for CI)
- Verify the auth token has appropriate permissions

## Optional: Public Cache

Consider making your cache public so others can benefit from your builds:

```bash
# Make your cache public (optional)
cachix set-public-read secmon-daemon
```

This allows anyone to use your cached builds without authentication, speeding up builds for users of your project.