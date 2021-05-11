
# Customised DMOZ URL extractor

# Adapted by Leon Ware

# Original code available at: https://github.com/SongweiGe/Dmoz-Dataset


# Example link:
# <link r:resource="http://www.firststateballet.com/"></link>

import re



# MAIN EXTRACTION SECTION

urls = []

print("Reading DMOZ file")

with open('content.rdf.u8', 'r', encoding='utf8') as file:
    for line in file:
##        cur_title = re.findall('<d:Title>(.+)</d:Title>', line)

        cur_url = re.findall('<link r:resource="(.+)"></link>', line)
        
        if cur_url:
            for item in range(len(cur_url)):
##                print(cur_url[item])
                urls.append(cur_url[item])

print("Writing output file")


with open('dmoz_urls.txt', 'w', encoding='utf8') as file:
    for i in range(len(urls)):
        file.write(urls[i] + "\n")



# CREATE SHORTENED VERSION

print("Creating shortened version - 1/3 URLs used")
line_num = 0
with open('dmoz_urls.txt', 'r', encoding='utf8') as in_file:
    with open('dmoz_urls_short.txt', 'w', encoding='ascii') as out_file:
        for line in in_file:
            if line_num % 3 == 0:
                try:
                    out_file.write(line)
                except UnicodeEncodeError:
                    line_num -= 1
            line_num += 1

print("Completed")
        

### extract the first 10000 line from the data
##with open('content.rdf.u8', 'r') as file:
##    lines = [str(line) for line in file]
##    
##    
##print("Finding data")
##    
### extract titles, sescriptions, and topics
##titles = [re.findall('<d:Title>(.+)</d:Title>', line) for line in lines]
##descs = [re.findall('<d:Description>(.+)</d:Description>', line) for line in lines]
##topics = [re.findall('<topic>(.+)</topic>', line) for line in lines]
##
##print("Done.")
##
##print(titles[0:10])



