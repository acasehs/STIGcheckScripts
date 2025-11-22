# Oracle Linux 8 STIG Automation Analysis

## Overview

**Total Checks**: 1003

**STIG Version**: Oracle Linux 8 Security Technical Implementation Guide :: Version 1, Release: 7

**Benchmark Date**: 26 Jul 2023

## Automation Summary

| Metric | Count | Percentage |
|--------|-------|------------|
| Fully Automated | 675 | 67.3% |
| Potentially Automated | 256 | 25.5% |
| Manual Review Required | 72 | 7.2% |
| Environment-Specific | 54 | 5.4% |
| Requires Third-Party Tools | 12 | 1.2% |
| **Total Automatable** | **931** | **92.8%** |

## Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| HIGH | 62 | 6.2% |
| MEDIUM | 860 | 85.7% |
| LOW | 81 | 8.1% |

## Tool Requirements

### Native Tools (Bash)
- File system commands: `find`, `ls`, `stat`, `chmod`, `chown`
- Configuration: `grep`, `cat`, `awk`, `sed`
- Package management: `rpm`, `yum`, `dnf`
- Services: `systemctl`
- SELinux: `getenforce`, `sestatus`, `getsebool`
- Firewall: `firewall-cmd`, `iptables`
- Audit: `auditctl`, `aureport`, `ausearch`
- Users: `getent`, `passwd`, `lastlog`
- Kernel: `sysctl`, `uname`
- Crypto: `openssl`, `update-crypto-policies`
- Network: `ip`, `ss`, `netstat`
- SSH: `sshd`, `ssh-keygen`
- Logging: `journalctl`, `rsyslog`

### Fallback (Python 3.6+)
- Standard library modules: `os`, `subprocess`, `pathlib`, `re`

### Third-Party Tools (When Required)
- AIDE (Advanced Intrusion Detection Environment)

## Configuration File Requirements

**54** checks (5.4%) require environment-specific values:

- **Requires approved/authorized values in config file**: 54 checks

## Detailed Check Analysis

| Vuln ID | Severity | Automation Status | Method | Elevation | Third-Party | Notes |
|---------|----------|-------------------|---------|-----------|-------------|-------|
| V-248519 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248520 | MEDIUM | Fully Automated | Bash (systemctl) | No | No |  |
| V-248521 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248522 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248523 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | Yes | Requires AIDE (Advanced Intrusion Detection Enviro |
| V-248524 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248525 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248526 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248527 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248528 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248529 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248530 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248531 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248532 | MEDIUM | Fully Automated | Bash (sshd -T, grep) | Yes | No |  |
| V-248533 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248534 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248535 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248537 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248538 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248539 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248540 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248541 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248542 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248543 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248544 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248545 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248546 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248547 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248548 | MEDIUM | Fully Automated | Bash (SELinux commands) | No | No |  |
| V-248549 | LOW | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248551 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248552 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248553 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248554 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248555 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248556 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248557 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248558 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248559 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248560 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248561 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248562 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248563 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248564 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248565 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248566 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248567 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248568 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248569 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248570 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248571 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248572 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248573 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | Yes | Requires AIDE (Advanced Intrusion Detection Enviro |
| V-248574 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248575 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248576 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248577 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248578 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248579 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248580 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248581 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248582 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248583 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248584 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248585 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248586 | LOW | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248587 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248588 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248589 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248590 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248591 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248592 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248593 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248594 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248595 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248596 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248597 | HIGH | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248598 | HIGH | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248599 | LOW | Fully Automated | Bash (systemctl) | No | No |  |
| V-248600 | LOW | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248601 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248602 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248603 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248605 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248606 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248607 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248608 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248609 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248610 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248611 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248612 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248613 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248615 | MEDIUM | Fully Automated | Bash (systemctl) | No | No |  |
| V-248616 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248617 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248618 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248619 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248620 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248621 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248622 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248623 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248624 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248625 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248626 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248627 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248628 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248629 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248630 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248631 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248632 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248633 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248634 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248635 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248636 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248637 | MEDIUM | Fully Automated | Bash (getent, passwd) | Yes | No |  |
| V-248638 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248639 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248640 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248641 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248642 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248643 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248644 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248645 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248646 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248647 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248648 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248649 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248650 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248651 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248652 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248653 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248654 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248655 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248656 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248657 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248658 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248659 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248660 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248661 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248662 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248663 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248664 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248665 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248666 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248667 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248668 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248669 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248670 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248671 | MEDIUM | Fully Automated | Bash (ip, ss, netstat) | No | No |  |
| V-248672 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248673 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248674 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248675 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248676 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248677 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248678 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248679 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248680 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248681 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248682 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248683 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248684 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248685 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248686 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248687 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248688 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248689 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248690 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248691 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248692 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248693 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248694 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248695 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248696 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248697 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248698 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248699 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248700 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248701 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248702 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248703 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248704 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248705 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248706 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248707 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248708 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248709 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248710 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248711 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248712 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248713 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248714 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248715 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248716 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248717 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248718 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248719 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248720 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248721 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248722 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248723 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248724 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248725 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248726 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248728 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248729 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248730 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248731 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248732 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248733 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248734 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248735 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248736 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248737 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248738 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248739 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248740 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248741 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248742 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248743 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248744 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248745 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248746 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248747 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248748 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248753 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248754 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248756 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248757 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248758 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248759 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248760 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248761 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248762 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248763 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248764 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248765 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248766 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248767 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248768 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248769 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248770 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248771 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248772 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248773 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248774 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248779 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248781 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248782 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248783 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248784 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248790 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248791 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248797 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248798 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248799 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248800 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248801 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248802 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248803 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248804 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248805 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248806 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248807 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248808 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248809 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248810 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | Yes | Requires AIDE (Advanced Intrusion Detection Enviro |
| V-248811 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248812 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248813 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248814 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248815 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248816 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248817 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248818 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248819 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248820 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248821 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248822 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248823 | HIGH | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248824 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248825 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248826 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248827 | HIGH | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248828 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248829 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248830 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248831 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248832 | LOW | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248833 | LOW | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248834 | LOW | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248835 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248836 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248837 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248839 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248840 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248841 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248842 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248843 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248844 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248845 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248846 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248847 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248848 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248849 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248850 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248851 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248852 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248853 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248854 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248855 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248856 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248857 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248858 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248859 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248860 | MEDIUM | Fully Automated | Bash (systemctl) | No | No |  |
| V-248861 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248862 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248863 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248864 | MEDIUM | Fully Automated | Bash (systemctl) | No | No |  |
| V-248865 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248866 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248867 | MEDIUM | Fully Automated | Bash (systemctl) | No | No |  |
| V-248868 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248869 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248870 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248871 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248872 | LOW | Fully Automated | Bash (systemctl) | No | No |  |
| V-248873 | HIGH | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248874 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248875 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248876 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248877 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248878 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248879 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248880 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248881 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248882 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248883 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248884 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248885 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248886 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248887 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248888 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248889 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248890 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248891 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248892 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248893 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248894 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248895 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248896 | LOW | Fully Automated | Bash (find, ls, stat) | Yes | Yes | Requires AIDE (Advanced Intrusion Detection Enviro |
| V-248897 | LOW | Fully Automated | Bash (find, ls, stat) | Yes | Yes | Requires AIDE (Advanced Intrusion Detection Enviro |
| V-248898 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248899 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248900 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248901 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248902 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248903 | HIGH | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248904 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248905 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248906 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248907 | MEDIUM | Fully Automated | Bash (systemctl) | No | No |  |
| V-252650 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-252651 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-252652 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-252653 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-252654 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | Yes | Requires AIDE (Advanced Intrusion Detection Enviro |
| V-252655 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-252656 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-252657 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-252658 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-252659 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-252660 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-252661 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-252662 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-252663 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-255898 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-256978 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-256979 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-257259 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248519 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248520 | MEDIUM | Fully Automated | Bash (systemctl) | No | No |  |
| V-248521 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248523 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | Yes | Requires AIDE (Advanced Intrusion Detection Enviro |
| V-248524 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248525 | HIGH | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248526 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248527 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248528 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248529 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248530 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248531 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248532 | MEDIUM | Fully Automated | Bash (sshd -T, grep) | Yes | No |  |
| V-248533 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248534 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248535 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248537 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248538 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248539 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248540 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248541 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248542 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248543 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248544 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248545 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248546 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248547 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248548 | MEDIUM | Fully Automated | Bash (SELinux commands) | No | No |  |
| V-248549 | LOW | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248551 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248552 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248553 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248554 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248555 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248556 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248557 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248558 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248559 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248560 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248561 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248562 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248563 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248564 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248565 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248566 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248567 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248568 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248569 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248570 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248571 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248572 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248573 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | Yes | Requires AIDE (Advanced Intrusion Detection Enviro |
| V-248574 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248575 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248576 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248577 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248578 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248579 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248580 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248581 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248582 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248583 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248584 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248585 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248586 | LOW | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248587 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248588 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248589 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248590 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248591 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248592 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248593 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248594 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248595 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248596 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248597 | HIGH | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248598 | HIGH | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248599 | LOW | Fully Automated | Bash (systemctl) | No | No |  |
| V-248600 | LOW | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248601 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248602 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248603 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248605 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248606 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248607 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248608 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248609 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248610 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248611 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248612 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248613 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248615 | MEDIUM | Fully Automated | Bash (systemctl) | No | No |  |
| V-248616 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248617 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248618 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248619 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248620 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248621 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248622 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248623 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248624 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248625 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248626 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248627 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248628 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248629 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248630 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248631 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248632 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248633 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248634 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248635 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248636 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248637 | MEDIUM | Fully Automated | Bash (getent, passwd) | Yes | No |  |
| V-248638 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248639 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248640 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248641 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248642 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248643 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248644 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248645 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248646 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248647 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248648 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248649 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248650 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248651 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248652 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248653 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248654 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248655 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248656 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248657 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248658 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248659 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248660 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248661 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248662 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248663 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248664 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248665 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248666 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248667 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248668 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248669 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248670 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248671 | MEDIUM | Fully Automated | Bash (ip, ss, netstat) | No | No |  |
| V-248672 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248673 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248674 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248675 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248676 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248677 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248678 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248679 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248680 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248681 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248682 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248683 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248684 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248685 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248686 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248687 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248688 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248689 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248690 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248691 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248692 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248693 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248694 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248695 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248696 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248697 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248699 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248700 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248701 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248702 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248703 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248704 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248705 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248706 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248707 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248708 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248709 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248710 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248711 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248712 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248713 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248714 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248715 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248716 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248717 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248718 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248719 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248720 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248721 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248722 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248723 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248724 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248725 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248726 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248728 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248729 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248730 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248731 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248732 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248733 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248734 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248735 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248736 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248737 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248738 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248739 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248740 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248741 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248742 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248743 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248744 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248745 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248746 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248747 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248748 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248753 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248754 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248756 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248757 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248758 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248759 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248760 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248761 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248762 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248763 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248764 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248765 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248766 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248767 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248768 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248769 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248770 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248771 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248772 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248773 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248774 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248779 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248781 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248782 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248783 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248784 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248790 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248791 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248797 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248798 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248799 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248800 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248801 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248802 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248803 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248804 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248805 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248806 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248807 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248808 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248809 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-248810 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | Yes | Requires AIDE (Advanced Intrusion Detection Enviro |
| V-248811 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248812 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248813 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248814 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248815 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248816 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248817 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248818 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248819 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248820 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248821 | LOW | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248822 | LOW | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248823 | HIGH | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248824 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248825 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248826 | LOW | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248827 | HIGH | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248828 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248829 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248830 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248831 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248832 | LOW | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248833 | LOW | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248834 | LOW | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248835 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248836 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248837 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248839 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248840 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248841 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248842 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248843 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248844 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248845 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248846 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248847 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248848 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248849 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248850 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248851 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248852 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248853 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248854 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248855 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248856 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248857 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248858 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248859 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248860 | MEDIUM | Fully Automated | Bash (systemctl) | No | No |  |
| V-248861 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248862 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248863 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248864 | MEDIUM | Fully Automated | Bash (systemctl) | No | No |  |
| V-248865 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248866 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248867 | MEDIUM | Fully Automated | Bash (systemctl) | No | No |  |
| V-248868 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248869 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248870 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248871 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248872 | LOW | Fully Automated | Bash (systemctl) | No | No |  |
| V-248873 | HIGH | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248874 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248875 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248876 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248877 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248878 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248879 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248880 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248881 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248882 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248883 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248884 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248885 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248886 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248887 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248888 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248889 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248890 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248891 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248892 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248893 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248894 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248895 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248896 | LOW | Fully Automated | Bash (find, ls, stat) | Yes | Yes | Requires AIDE (Advanced Intrusion Detection Enviro |
| V-248897 | LOW | Fully Automated | Bash (find, ls, stat) | Yes | Yes | Requires AIDE (Advanced Intrusion Detection Enviro |
| V-248898 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248899 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248900 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248901 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248902 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248903 | HIGH | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-248904 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248905 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248906 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-248907 | MEDIUM | Fully Automated | Bash (SELinux commands) | No | No |  |
| V-252650 | HIGH | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-252651 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-252652 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-252653 | MEDIUM | Fully Automated | Bash (find, ls, stat) | Yes | No |  |
| V-252654 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | Yes | Requires AIDE (Advanced Intrusion Detection Enviro |
| V-252655 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-252656 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-252657 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-252658 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-252659 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-252660 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-252662 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-252663 | MEDIUM | Manual Review Required | N/A | No | No | Requires policy/documentation review |
| V-255898 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-256978 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-256979 | MEDIUM | Fully Automated | Bash (rpm, yum, dnf) | No | No |  |
| V-257259 | MEDIUM | Fully Automated | Bash (grep, cat, awk) | Yes | No |  |
| V-248519 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248520 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248521 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248524 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248527 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248533 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248534 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248535 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248537 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248540 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248541 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248542 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248543 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248544 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248545 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248546 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248547 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248549 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248552 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248554 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248555 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248556 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248557 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248558 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248559 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248563 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248565 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248567 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248574 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248575 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248577 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248578 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248579 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248580 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248581 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248582 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248583 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248584 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248585 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248586 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248595 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248596 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248597 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248598 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248601 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248602 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248603 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248605 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248606 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248607 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248608 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248609 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248610 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248611 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248613 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248615 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248617 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248619 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248624 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248625 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248626 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248629 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248632 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248633 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248644 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248649 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248650 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248652 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248653 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248654 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248655 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248656 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248657 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248660 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248661 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248662 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248663 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248664 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248665 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248666 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248674 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248675 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248677 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248686 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248687 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248688 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248689 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248690 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248691 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248692 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248693 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248694 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248695 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248696 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248697 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248699 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248700 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248705 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248706 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248707 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248709 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248710 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248711 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248712 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248714 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248715 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248716 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248717 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248718 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248719 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248722 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248724 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248726 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248728 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248729 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248730 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248731 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248732 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248733 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248734 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248735 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248736 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248737 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248738 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248739 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248740 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248741 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248742 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248743 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248744 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248745 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248746 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248747 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248748 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248753 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248754 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248756 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248757 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248758 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248759 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248760 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248761 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248762 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248763 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248764 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248765 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248766 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248767 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248768 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248769 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248770 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248771 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248772 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248773 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248774 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248779 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248781 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248782 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248783 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248784 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248790 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248791 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248797 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248798 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248799 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248800 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248802 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248806 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248807 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248808 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248809 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248812 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248813 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248815 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248818 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248821 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248822 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248823 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248824 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248825 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248827 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248829 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248830 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248831 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248832 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248833 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248834 | LOW | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248837 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248840 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248841 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248843 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248844 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248845 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248846 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248847 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248848 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248849 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248850 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248851 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248852 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248853 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248854 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248855 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248856 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248857 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248858 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248859 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248862 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248867 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248868 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248870 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248871 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248873 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248874 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248875 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248876 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248877 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248878 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248879 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248880 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248881 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248882 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248883 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248884 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248885 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248886 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248887 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248888 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248889 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248890 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248891 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248892 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248893 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248894 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248895 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248900 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248901 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248902 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248903 | HIGH | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248904 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248905 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-248906 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-252658 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |
| V-257259 | MEDIUM | Potentially Automated | Requires custom bash/python script | No | No | Check content needs detailed analysis |

## Sample Check Implementation

See the following directories for sample implementations:

- `samples/` - Sample bash and python checks
- `stig-config.json` - Environment-specific configuration file
- `CONFIG-GUIDE.md` - Configuration customization guide
- `EXAMPLE-OUTPUT.md` - Example check outputs with audit evidence

## Usage

### Basic Check (Default Values)
```bash
# Bash (preferred)
bash V-252518.sh

# Python (fallback)
python3 V-252518.py
```

### With Configuration File
```bash
# Bash with environment-specific values
bash V-252518.sh --config stig-config.json

# Python with environment-specific values
python3 V-252518.py --config stig-config.json
```

### With JSON Output
```bash
bash V-252518.sh --config stig-config.json --output-json results.json
```

