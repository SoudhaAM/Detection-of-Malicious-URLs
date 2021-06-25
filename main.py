import csv
import Feature_extraction as urlfeature
import trainer as tr
def process_test_url(url,output_dest):
    feature=[]
    url=url.strip()
    if url!='':
        print ('Working on:'+url)
        ret_dict=urlfeature.feature_extract(url)
        feature.append([url,ret_dict]);
    resultwriter(feature,output_dest)

def resultwriter(feature,output_dest):
    flag = True
    with open(output_dest,'w') as f:
        for item in feature:
            w = csv.DictWriter(f, item[1].keys())
            if flag:
                w.writeheader()
                flag=False
            w.writerow(item[1])
