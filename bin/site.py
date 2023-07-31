import yaml
import argparse
import sys
import re
import os
import json
import datetime
import jinja2
import csv

def write_bootkits_csv(bootkits, output_dir, VERBOSE):
    output_file = os.path.join(output_dir, 'content', 'api', 'bootkits.csv')
    
    header = ['Id', 'Author', 'Created', 'Command', 'Description', 'Usecase', 'Category', 'Privileges', 'MitreID',
              'OperatingSystem', 'Resources', 'bootkit Description', 'Person', 'Handle', 'Detection',
              'KnownVulnerableSamples_MD5', 'KnownVulnerableSamples_SHA1', 'KnownVulnerableSamples_SHA256',
              'KnownVulnerableSamples_Publisher', 'KnownVulnerableSamples_Date',
              'KnownVulnerableSamples_Company', 'KnownVulnerableSamples_Description', 
              'KnownVulnerableSamples_Authentihash_MD5', 'KnownVulnerableSamples_Authentihash_SHA1', 'KnownVulnerableSamples_Authentihash_SHA256', 'Verified', 'Tags']

    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()

        for bootkit in bootkits:
            if VERBOSE:
                print(f"Writing bootkit CSV: {bootkit['Id']}")

            md5s = [s['MD5'] for s in bootkit['KnownVulnerableSamples'] if 'MD5' in s]
            sha1s = [s['SHA1'] for s in bootkit['KnownVulnerableSamples'] if 'SHA1' in s]
            sha256s = [s['SHA256'] for s in bootkit['KnownVulnerableSamples'] if 'SHA256' in s]
            publishers = [s['Publisher'] for s in bootkit['KnownVulnerableSamples'] if 'Publisher' in s]
            dates = [s['Date'] for s in bootkit['KnownVulnerableSamples'] if 'Date' in s]
            companies = [s['Company'] for s in bootkit['KnownVulnerableSamples'] if 'Company' in s]
            descriptions = [s['Description'] for s in bootkit['KnownVulnerableSamples'] if 'Description' in s]
            authentihash_md5s = [s['Authentihash']['MD5'] for s in bootkit['KnownVulnerableSamples'] if 'Authentihash' in s]
            authentihash_sha1s = [s['Authentihash']['SHA1'] for s in bootkit['KnownVulnerableSamples'] if 'Authentihash' in s]
            authentihash_sha256s = [s['Authentihash']['SHA256'] for s in bootkit['KnownVulnerableSamples'] if 'Authentihash' in s]

        
            row = {
                'Id': bootkit.get('Id', ''),
                'Author': bootkit.get('Author', ''),
                'Created': bootkit.get('Created', ''),
                'Command': bootkit.get('Command', ''),
                'Description': bootkit.get('Description', ''),
                'Usecase': bootkit.get('Usecase', ''),
                'Category': bootkit.get('Category', ''),
                'Privileges': bootkit.get('Privileges', ''),
                'MitreID': bootkit.get('MitreID', ''),
                'OperatingSystem': bootkit.get('OperatingSystem', ''),
                'Resources': bootkit.get('Resources', ''),
                'bootkit Description': bootkit.get('bootkit Description', ''),
                'Person': bootkit.get('Person', ''),
                'Handle': bootkit.get('Handle', ''),
                'Detection': bootkit.get('Detection', ''),
                'KnownVulnerableSamples_MD5': ', '.join(str(md5) for md5 in md5s),
                'KnownVulnerableSamples_SHA1': ', '.join(str(sha1) for sha1 in sha1s),
                'KnownVulnerableSamples_SHA256': ', '.join(str(sha256) for sha256 in sha256s),
                'KnownVulnerableSamples_Publisher': ', '.join(str(publisher) for publisher in publishers),
                'KnownVulnerableSamples_Date': ', '.join(str(date) for date in dates),
                'KnownVulnerableSamples_Company': ', '.join(str(company) for company in companies),
                'KnownVulnerableSamples_Description': ', '.join(str(description) for description in descriptions),
                'KnownVulnerableSamples_Authentihash_MD5': ', '.join(str(md5) for md5 in authentihash_md5s),
                'KnownVulnerableSamples_Authentihash_SHA1': ', '.join(str(sha1) for sha1 in authentihash_sha1s),
                'KnownVulnerableSamples_Authentihash_SHA256': ', '.join(str(sha256) for sha256 in authentihash_sha256s),
                'Verified': bootkit.get('Verified', ''),
                'Tags': ', '.join(str(tag) for tag in bootkit['Tags'])                                  
            }

            writer.writerow(row)





def write_top_products(bootkits, output_dir, top_n=5):
    products_count = {}

    for bootkit in bootkits:
        for hash_info in bootkit['KnownVulnerableSamples']:
            product_name = hash_info['Product']

            if not product_name:
                continue

            product_name = product_name.strip().replace(',', '')

            if product_name.lower() == 'n/a' or product_name.isspace():
                continue

            if product_name not in products_count:
                products_count[product_name] = 0

            products_count[product_name] += 1

    sorted_products = sorted(products_count.items(), key=lambda x: x[1], reverse=True)[:top_n]

    with open(f"{output_dir}/content/bootkits_top_{top_n}_products.csv", "w") as f:
        writer = csv.writer(f)

        for product, count in sorted_products:
            for _ in range(count):
                writer.writerow([count, product])

def write_top_publishers(bootkits, output_dir, top_n=5):
    publishers_count = {}

    for bootkit in bootkits:
        for hash_info in bootkit['KnownVulnerableSamples']:
            publisher_str = hash_info.get('Publisher')  # Use the `get()` method here

            if not publisher_str:
                continue

            publishers = re.findall(r'\"(.*?)\"|([^,]+)', publisher_str)
            for publisher_tuple in publishers:
                publisher = next(filter(None, publisher_tuple)).strip()

                if publisher.lower() == 'n/a' or publisher.isspace() or publisher.lower() == 'ltd.':
                    continue

                if publisher not in publishers_count:
                    publishers_count[publisher] = 0

                publishers_count[publisher] += 1

    sorted_publishers = sorted(publishers_count.items(), key=lambda x: x[1], reverse=True)[:top_n]

    with open(f"{output_dir}/content/bootkits_top_{top_n}_os.csv", "w") as f:
        writer = csv.writer(f)

        for publisher, count in sorted_publishers:
            for _ in range(count):
                writer.writerow([count, publisher])



def generate_doc_bootkits(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, messages, VERBOSE):
    manifest_files = []
    for root, dirs, files in os.walk(REPO_PATH):
        for file in files:
                manifest_files.append((os.path.join(root, file)))

    bootkits = []
    for manifest_file in manifest_files:
        bootkit = dict()
        if VERBOSE:
            print("processing bootkit {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                sys.exit(1)

        bootkits.append(object)

    # write markdowns
    j2_env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_PATH), trim_blocks=True, autoescape=True, lstrip_blocks=False)
    d = datetime.datetime.now()
    template = j2_env.get_template('bootkit.md.j2')
    for bootkit in bootkits:
        file_name = bootkit["Id"] + '.md'
        output_path = os.path.join(OUTPUT_DIR + '/content/bootkits/' + file_name)
        output = template.render(bootkit=bootkit, time=str(d.strftime("%Y-%m-%d")))
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
    messages.append("site_gen.py wrote {0} bootkits markdown to: {1}".format(len(bootkits),OUTPUT_DIR + '/content/bootkits/'))

    # write api csv
    write_bootkits_csv(bootkits, OUTPUT_DIR, VERBOSE)
    messages.append("site_gen.py wrote bootkits CSV to: {0}".format(OUTPUT_DIR + '/content/api/bootkits.csv'))

    # write api json
    with open(OUTPUT_DIR + '/content/api/' + 'bootkits.json', 'w', encoding='utf-8') as f:
        json.dump(bootkits, f, ensure_ascii=False, indent=4)
    messages.append("site_gen.py wrote bootkits JSON to: {0}".format(OUTPUT_DIR + '/content/api/bootkits.json'))

    # write listing csv
    with open(OUTPUT_DIR + '/content/' + 'bootkits_table.csv', 'w') as f:
        writer = csv.writer(f)
        for bootkit in bootkits:
            link = '[' + bootkit['Tags'][0] + '](bootkits/' + bootkit["Id"] + '/)'
            if ('SHA256' not in bootkit['KnownVulnerableSamples'][0]) or (bootkit['KnownVulnerableSamples'][0]['SHA256'] is None ) or (bootkit['KnownVulnerableSamples'][0]['SHA256'] == ''):
                sha256='not available '
            else:
                sha256='[' + bootkit['KnownVulnerableSamples'][0]['SHA256'] + '](bootkits/' + bootkit["Id"]+ '/)'
            writer.writerow([link, sha256, bootkit['Category'].capitalize(), bootkit['Created']])
    messages.append("site_gen.py wrote bootkits table to: {0}".format(OUTPUT_DIR + '/content/bootkits_table.csv'))

    # write top 5 products
    write_top_products(bootkits, OUTPUT_DIR)
    messages.append("site_gen.py wrote bootkits products to: {0}".format(OUTPUT_DIR + '/content/bootkits_top_n_products.csv'))

    return bootkits, messages


if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="Generates bootloaders.io site", epilog="""
    This tool converts all bootloaders.io yamls and builds the site with all the supporting components.""")
    parser.add_argument("-p", "--path", required=False, default="yaml", help="path to lolbootkit yaml folder. Defaults to `yaml`")
    parser.add_argument("-o", "--output", required=False, default="bootloaders.io", help="path to the output directory for the site, defaults to `bootloaders.io`")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")

    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    OUTPUT_DIR = args.output
    VERBOSE = args.verbose


    TEMPLATE_PATH = os.path.join(REPO_PATH, '../bin/jinja2_templates')

    if VERBOSE:
        print("wiping the {0}/content/bootkits/ folder".format(OUTPUT_DIR))

    # first clean up old bootkits
    try:
        for root, dirs, files in os.walk(OUTPUT_DIR + '/content/bootkits/'):
            for file in files:
                if file.endswith(".md") and not file == '_index.md':
                    os.remove(root + '/' + file)
    except OSError as e:
        print("error: %s : %s" % (file, e.strerror))
        sys.exit(1)


    # also clean up API artifacts
    if os.path.exists(OUTPUT_DIR + '/content/api/bootkits.json'):
        os.remove(OUTPUT_DIR + '/content/api/bootkits.json')         
    if os.path.exists(OUTPUT_DIR + '/content/api/bootkits.csv'):        
        os.remove(OUTPUT_DIR + '/content/api/bootkits.csv')


    messages = []
    bootkits, messages = generate_doc_bootkits(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, messages, VERBOSE)

    # print all the messages from generation
    for m in messages:
        print(m)
    print("finished successfully!")
