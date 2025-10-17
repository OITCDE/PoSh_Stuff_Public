## ⚠️ Important Disclaimer

### AI-Assisted Development
These scripts have been developed with the assistance of **Claude 4.5 Sonnet (Anthropic AI)** and rigorously tested in real-world enterprise environments to ensure functionality, reliability, and adherence to best practices.

### Testing & Validation
All scripts have been validated through:
- ✅ Real-world Active Directory environments
- ✅ Multiple scenarios and edge cases
- ✅ Troubleshooting actual production issues
- ✅ Iterative refinement based on practical use

### Usage Guidelines

> **⚠️ CRITICAL: These scripts are provided "AS IS" without warranty of any kind.**

**Before deploying to production:**

1. **Test thoroughly** in a non-production/lab environment first
2. **Review the code** to understand what it does
3. **Backup your systems** before making any changes
4. **Validate results** in your specific environment
5. **Use with caution** - especially scripts that modify AD objects

**The author(s) and contributors assume NO responsibility for:**
- Data loss or corruption
- System downtime or service interruptions  
- Security vulnerabilities introduced through misconfiguration
- Any damages resulting from the use of these scripts

### Recommended Approach

```powershell
# Always start with DryRun mode when available
.\Script.ps1 -DryRun:$true

# Review the output and logs carefully
# Only proceed to live execution after thorough validation

Your IT environment is unique - always adapt scripts to your specific needs and policies!
