from py2neo import *
import pandas as pd
import difflib

def insert_cve(cve_read):#86348
    cve_list=[]
    length=len(cve_read['cveID'])
    for i in range(length):
        cveid=cve_read['cveID'][i]
        cve_list.append(cveid)

    cve_list=list(set(cve_list))
    # 导入到neo4j
    i = 0
    for cveid in cve_list:
        centence = "CREATE (n:CVE {name: '" + cveid + "'})"
        cypher = centence
        cursor = graph.run(cypher)
        i=i+1
        print(i)

def insert_affect_product(cve_read):#43838
    product_list=[]
    length=len(cve_read['cpe23Uri'])
    k=0
    for i in range(length):
        product=cve_read['cpe23Uri'][i].split(':')[4]
        product=product.replace('/','')
        product=product.replace('\\','_')
        product=product.replace("'",'')
        versionstart = str(cve_read['versionStartIncluding'][i])
        versionstart = versionstart.replace('\\', '')
        versionend=str(cve_read['versionEndExcluding'][i])
        versionend=versionend.replace('\\',',')
        concat_string=product+':'+versionstart+':'+versionend
        product_list.append(concat_string)
    product_list = list(set(product_list))
    # print(product_list)

        #导入到neo4j
    for info in product_list:
        product=info.split(':')[0]
        versionstart=info.split(':')[1]
        versionend=info.split(':')[2]
        # print(product,versionstart,versionend)
        centence = "CREATE (n:Product {name: '" + product + "',versionStartIncluding: '" + versionstart + "',versionEndExcluding: '"+versionend+"'})"
        cypher = centence
        cursor = graph.run(cypher)
        k=k+1
        print(k)

def insert_node(csv_read):#55057
    concat_list = []
    length = len(csv_read['package_name'])
    # 在导入节点时要做一步去重
    for i in range(length):
        concat_string = csv_read['package_name'][i] + ',' + csv_read['package_version'][i]
        # concat_string=concat_string.replace('-','_')
        concat_list.append(concat_string)
    concat_list = list(set(concat_list))
    # 导入到neo4j
    i=0
    for content in concat_list:
        package_name = content.split(',')[0]
        package_version = content.split(',')[1]
        print(package_name, package_version)
        centence = "CREATE (n:Package {name: '" + package_name + "',version: '" + package_version + "'})"
        cypher = centence
        cursor = graph.run(cypher)
        i=i+1
        print(i)

def insert_relationship(csv_read):#266287
    length = len(csv_read['package_name'])
    k=0
    for i in range(length):
        package_name=csv_read['package_name'][i]
        depend_name=csv_read['depend_name'][i]
        depend_name=depend_name.strip()
        depend_version=csv_read['depend_version'][i]
        # print(package_name,depend_name,depend_version)
        centence='MATCH (a:Package), (b:Package) WHERE a.name = "'+package_name+'" AND b.name = "'+depend_name+'"  CREATE (a)-[r:DEPEND{start:"'+package_name+'",end:"'+depend_name+'",relation:"depend"}]->(b)'
        # print(relation_string)
        cypher = centence
        cursor = graph.run(cypher)
        k=k+1
        print(k)

def insert_cve_to_product(cve_read):#170000+
    cve_product_list=[]
    length = len(cve_read['cveID'])
    k=0
    for i in range(length):
        cveid=cve_read['cveID'][i]
        product = cve_read['cpe23Uri'][i].split(':')[4]
        product = product.replace('/', '')
        product = product.replace('\\', '_')
        product = product.replace("'", '')
        versionstart = str(cve_read['versionStartIncluding'][i])
        versionstart = versionstart.replace('\\', '')
        versionend = str(cve_read['versionEndExcluding'][i])
        versionend = versionend.replace('\\', ',')
        concat_string =cveid+':'+ product + ':' + versionstart + ':' + versionend
        cve_product_list.append(concat_string)
    cve_product_list = list(set(cve_product_list))

    #将cve和其影响的产品关系导入neo4j
    for info in cve_product_list:
        cveid=info.split(':')[0]
        product=info.split(':')[1]
        versionstart=info.split(':')[2]
        versionend=info.split(':')[3]
        # print(cveid,product)
        centence="MATCH (a:CVE), (b:Product) WHERE a.name = '"+cveid+"' AND b.name = '"+product+"' AND b.versionStartIncluding='"+versionstart+"' AND b.versionEndExcluding='"+versionend+"' CREATE (a)-[r:AFFECT{start:'"+cveid+"',end:'"+product+"',relation:'affect'}]->(b)"
        cypher = centence
        cursor = graph.run(cypher)
        k=k+1
        print(k)

def insert_product_to_node(cve_read,csv_read):#卡在了945，感觉差不多够了就没有重新跑了
    package_name_list = []
    product_list = []
    for cpe23Uri in cve_read['cpe23Uri']:
        product=cpe23Uri.split(':')[4]
        product = product.replace('/', '')
        product = product.replace('\\', '_')
        product = product.replace("'", '')
        product_list.append(product)
    product_list=list(set(product_list))

    for package_name in csv_read['package_name']:
        package_name_list.append(package_name)
    package_name_list=list(set(package_name_list))

    # 此处使用difflib库中的get_close_matches方法做字符串模糊匹配,匹配度设置为0.9时准确度最高，0.8时有用的匹配结果跟多，为了准确度这里设置为0.9
    # 可以用命名实体识别
    i=0
    for product in product_list:
        result_list = difflib.get_close_matches(product, package_name_list, 10, 0.9)
        if len(result_list) > 0:
            # print(product, result_list, len(result_list))
            for result in result_list:
                # 将受影响的产品和其对应的包名关系导入neo4j
                centence = "MATCH (a:Product), (b:Package) WHERE a.name = '" + product + "' AND b.name = '" + result + "' CREATE (a)-[r:LINK{start:'"+product+"',end:'"+result+"',relation:'link'}]->(b)"
                # print(centence)
                cypher = centence
                cursor=graph.run(cypher)
                i=i+1
                print(i)

if __name__=="__main__":
    # package_name_list = []
    graph=Graph('http://localhost:7474/',user='neo4j',password='root')
    df_package = pd.read_csv('./package.csv')
    df_cve = pd.read_csv('./cve.csv')
    # insert_cve(df_cve)
    # insert_affect_product(df_cve)
    # insert_node(df_package)
    # insert_cve_to_product(df_cve)
    # insert_relationship(df_package)
    # insert_product_to_node(df_cve,df_package)
