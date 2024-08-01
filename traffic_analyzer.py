import argparse
import pandas as pd
import requests

'''
Usage:
python traffic_analyzer.py logs_analyst.csv --googlebot
python traffic_analyzer.py logs_analyst.csv --badbot
python traffic_analyzer.py logs_analyst.csv --human
'''

pd.set_option('display.max_colwidth', None)

def identify_google_bot(dataset, boolvalue):
  """
  The signals used in this function are as follows:
  - Signal 1: is Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
  - Signal 2: GOOGLE in apiIpAutonomousSystemOrganization
  - Singal 3: IP addresses. Legitimate ip addresses are 66.249.xxx
  - Signal 4: fingerprintRequestJsWebGlRend	fingerprintRequestJsWebDriver	fingerprintRequestJsHardwareConcu are null or NaN for legitimate google bots.
    the negative of that is not a legitimate google bots. It could either then be human behavior or fraudulent activity.
    Language acceptance is supported therefore it is excluded here. (source: https://developers.google.com/search/blog/2015/01/crawling-and-indexing-of-locale)
  - Signal 5: apiEndpoint must be http. Googlebot can crawl the first 15MB of an HTML file or supported text-based file. (source: https://developers.google.com/search/docs/advanced/crawling/googlebot )
  - Signal 6: fingerprintAccept that does contatin text/html at the very least
  """
    ip_regex = "(66.249.\d{2})"
    useragent_regex = "(^Mozilla.\d.\d..compatible;.Googlebot.\d.\d.+)"
    text_html_regex = "(text.html)"

    signals_1_3_6 = dataset[(dataset['fingerprintUserAgent'].str.match(useragent_regex) == boolvalue) &
                            (dataset['fingerprintClientIp'].str.match(ip_regex) == boolvalue) &
                            (dataset['fingerprintAccept'].str.match(text_html_regex) == boolvalue)]

    if boolvalue:
        signals_2_4_5 = signals_1_3_6[(signals_1_3_6['apiEndpoint'] == 'http') & 
                                      (signals_1_3_6['apiIpAutonomousSystemOrganization'] == 'GOOGLE')]
        signal_6 = signals_2_4_5[signals_2_4_5['fingerprintRequestJsWebGlRend'].isnull() & 
                                 signals_2_4_5['fingerprintRequestJsWebDriver'].isnull() & 
                                 signals_2_4_5['fingerprintRequestJsHardwareConcu'].isnull()]
    else:
        signals_2_4_5 = signals_1_3_6[signals_1_3_6['apiIpAutonomousSystemOrganization'] != 'GOOGLE']
        signal_6 = signals_2_4_5
    return signal_6

def identify_bad_bot_traffic(dataset):
    """
  This function detects activities from non-identified bots, fake google bots, known bad bots and the user of libraries and net-tools.
  heuristic algorithm: identify_bad_bot_traffic=(¬identify_google_bot)^(bad_bots_signals)

  - Signal 1: is NOT Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
  - Signal 2: GOOGLE is NOT in apiIpAutonomousSystemOrganization
  - Singal 3: IP addresses are NOT 66.249.xxx
  - Signal 4: fingerprintRequestJsWebGlRend	fingerprintRequestJsWebDriver	fingerprintRequestJsHardwareConcu are NOT null or NaN for legitimate google bots.
    the negative of that is not a legitimate google bots. It could either then be human behavior or fraudulent activity.
    Language acceptance is supported therefore it is excluded here. (source: https://developers.google.com/search/blog/2015/01/crawling-and-indexing-of-locale)

  The signals used to identify non-identified bots are as follows:
  - Signal 1: no user-agent

  The signals used to identify fake bots are as follows:
  - Signal 1: the user-agent value contains Googlebot
  - Signal 2: the IP address does not belong to Google

  The signals used to identify known bad bots are as follows:
  - Signal 1: the user-agent dynamically matches a string in a publicly available list of bad bots.

  The signals used to identify the use of librairies and net tools are as follows:
  - Signal 1: the string curl is present with its corresponding version
  - Signal 2: the string python is present with its corresponding library name and version
  - Signal 3: the string Postman is present with its corresponding version

  The signals used to detect path traversal attacks:
  - Signal 1: fingerprintRequestUrl containing "/../"

  """
    curl_regex = "(^curl.\d.\d.+)"
    python_requests_regex = "(^python.requests.\d.\d.+)"
    postmanRuntime_regex = "(^PostmanRuntime.\d.+)"
    libraries_nettools = [curl_regex, python_requests_regex, postmanRuntime_regex]
    path_traversal_regex = "(.+/\../\.+)"
    rows = []

    badbotlist_URL = "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list"
    r = requests.get(url=badbotlist_URL, stream=True)

    for line in r.iter_lines():
        if line:
            rg = str(line, 'utf-8')
            out = dataset[dataset['fingerprintUserAgent'].str.match("(^.+" + rg + ")") == True]
            if not out.empty:
                print("Requests from Known Bad Bot Detected!")
                print("Found Known Bad Bot: " + rg)
                print("Number of requests: " + str(out.shape[0]))
                rows.append([rg, out.shape[0]])
                print(out)

    for libnetool in libraries_nettools:
        out = dataset[dataset['fingerprintUserAgent'].str.match(libnetool) == True]
        if not out.empty:
            print("Requests from Library or net tools detected!")
            print("Found Library or net tools: " + libnetool)
            print("Number of requests: " + str(out.shape[0]))
            lib_name = libnetool.split(".")[0].strip("^")
            rows.append([lib_name, out.shape[0]])
            print(out)

    statictics_df = pd.DataFrame(rows, columns=["Known Bad Bot", "Number of Requests"])
    print(statictics_df.sort_values(by=['Number of Requests'], ascending=False))

    googlebot_ua_regex = "(^Mozilla.\d.\d..compatible;.Googlebot.\d.\d.+)"
    googlebot_ip_regex = "(^66.249.\d{2})"
    fake_google_bots = dataset[(dataset['fingerprintClientIp'].str.match((googlebot_ip_regex)) == False) & 
                               (dataset['fingerprintUserAgent'].str.match((googlebot_ua_regex)) == True)]
    print("Fake Google Bots Detected!")
    print("Number of requests from fake google bots: " + str(fake_google_bots.shape[0]))
    print(fake_google_bots)

    pt = dataset[dataset['fingerprintRequestUrl'].str.match(path_traversal_regex) == True]
    if not pt.empty:
        print("Path traversal attacks detected!")
        print(pt)

def identify_human_traffic(dataframe):
  
    """
  This function detects human activity by using the following heuristic algorithm:
  human traffic = (¬google bots)^(¬fake google bots)^(¬non-identified bots)^(¬libraries and net tools)

  The signals used to remove fake bots are as follows:
  - Signal 1: the user-agent value does not contain Googlebot
  - Signal 2: the IP address does not belong to Google
  - Signal 3: non-null user-agent

  The signals used to remove known bad bots are as follows:
  - Signal 1: the user-agent does not dynamically matche a string in a publicly available list of bad bots.

  The signals used to remove the use of librairies and net tools are as follows:
  - Signal 1: the string curl is not present with its corresponding version
  - Signal 2: the string python is not present with its corresponding library name and version
  - Signal 3: the string Postman is not present with its corresponding version

  Negative of Path Traversal Attack Signals
  - Signal 1: the string "/../" is not in fingerprintRequestUrl
  """
  
    curl_regex = "^curl.\d.\d.+"
    python_requests_regex = "^python.requests.\d.\d.+"
    postmanRuntime_regex = "^PostmanRuntime.\d.\d.+"
    path_traversal_regex = "(.+/\../\.+)"
    benign_Bots = ".+Bot"
    benign_bots = ".+bot"
    unwanted_signals = [curl_regex, python_requests_regex, postmanRuntime_regex, benign_bots, benign_Bots]
    m_out = []

    noGoogleBots_df = identify_google_bot(dataframe, False)

    for filter in unwanted_signals:
        m_out = noGoogleBots_df[noGoogleBots_df['fingerprintUserAgent'].str.match("(" + filter + ")") == False]
        noGoogleBots_df = m_out

    m_out = noGoogleBots_df[noGoogleBots_df['fingerprintRequestUrl'].str.match("(" + path_traversal_regex + ")") == False]

    badbotlist_URL = "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list"
    r = requests.get(url=badbotlist_URL, stream=True)
    for line in r.iter_lines():
        if line:
            rg = str(line, 'utf-8')
            out = m_out[m_out['fingerprintUserAgent'].str.match("(^.+" + rg + ")") == False]
            if not out.empty:
                m_out = out
    return m_out

def main():
    parser = argparse.ArgumentParser(description="Analyze website traffic logs.")
    parser.add_argument('file', help="The CSV file containing the logs to analyze.")
    parser.add_argument('--googlebot', action='store_true', help="Identify Google bot traffic.")
    parser.add_argument('--badbot', action='store_true', help="Identify bad bot traffic.")
    parser.add_argument('--human', action='store_true', help="Identify human traffic.")
    args = parser.parse_args()

    df = pd.read_csv(args.file, sep='~')

    if args.googlebot:
        print("Identifying Google Bots...")
        google_bots = identify_google_bot(df, True)
        print(google_bots)

    if args.badbot:
        print("\nIdentifying Bad Bot Traffic...")
        identify_bad_bot_traffic(df)

    if args.human:
        print("\nIdentifying Human Traffic...")
        human_traffic = identify_human_traffic(df)
        print(human_traffic)

if __name__ == "__main__":
    main()
