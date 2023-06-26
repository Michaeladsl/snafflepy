from ldap3 import *
from time import sleep
import sys

def begin_snaffle(options):
    print("Beginning the snaffle...")
    sleep(0.2)
    print(options)

    # TESTING
    if options.test:
        server = Server('testing server', get_info=ALL)
        conn = Connection(server, user='cn=user0,ou=test,o=lab', password='test0000', client_strategy=MOCK_SYNC)

        conn.strategy.add_entry('cn=user0,ou=test,o=lab', {'userPassword': 'test0000', 'sn': 'user0_sn', 'revision': 0})
        conn.strategy.add_entry('cn=user1,ou=test,o=lab', {'userPassword': 'test1111', 'sn': 'user1_sn', 'revision': 0})
        conn.strategy.add_entry('cn=user2,ou=test,o=lab', {'userPassword': 'test2222', 'sn': 'user2_sn', 'revision': 0})
    
        if conn.bind():
            print(server.info)
        else:
            print("Error connecting to domain")
            print(conn.result)
            sys.exit(2)

    else :  
        server = Server(options.dcip, get_info=ALL)
        conn = Connection(server)
        
        if conn.bind():
            print(server.info)
        else:
            print("Error connecting to domain")
            print(conn.result)
            sys.exit(2)