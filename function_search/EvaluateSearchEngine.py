# SAFE TEAM
# distributed under license: GPL 3 License http://www.gnu.org/licenses/

from function_search.FunctionSearchEngine import FunctionSearchEngine
from sklearn import metrics
import sqlite3

import os
from multiprocessing import Process
import math
from pathlib import Path

import warnings
import random
import json

class SearchEngineEvaluator:

    def __init__(self, db_name, table, limit=None,k=None):
        self.tables = table
        self.db_name = db_name
        self.SE = FunctionSearchEngine(db_name, table, limit=limit)
        self.k=k
        self.number_similar={}

    def do_search(self, target_db_name, target_fcn_ids):
        self.SE.load_target(target_db_name, target_fcn_ids)
        self.SE.pp_search(50)

    def calc_auc(self, target_db_name, target_fcn_ids):
        self.SE.load_target(target_db_name, target_fcn_ids)
        result = self.SE.auc()
        print(result)

    #
    # This methods searches for all target function in the DB, in our test we take num functions compiled with compiler and opt
    # moreover it populates the self.number_similar dictionary, that contains the number of similar function for each target
    #
    def find_target_fcn(self, compiler, opt, num):
        """ Randomly choose some records from the tables "functions" and fetch the total number of each similar function.

        Records would be chosen with the conditions "compiler" and "opt". 
        The num of the records returned is the smaller value of "num" and the total number of the records.

        Args:
            compiler (str):
            opt (str):
            num (int):

        Returns:
            A tuple that has two arrays: 
                the first array contains the ids and 
                the second array contains the labels of the randomly chosen functions.
        """
        conn = sqlite3.connect(self.db_name)
        cur = conn.cursor()
        q = cur.execute("SELECT id, project, file_name, function_name FROM functions WHERE compiler=? AND optimization=?", (compiler, opt))
        res = q.fetchall()
        ids = [i[0] for i in res]
        true_labels = [l[1]+"/"+l[2]+"/"+l[3] for l in res]
        n_ids = []
        n_true_labels = []
        num = min(num, len(ids))

        for i in range(0, num):
            index = random.randrange(len(ids))
            n_ids.append(ids[index])
            n_true_labels.append(true_labels[index])
            f_name=true_labels[index].split('/')[2]
            fi_name=true_labels[index].split('/')[3]
            q = cur.execute("SELECT num FROM count_func WHERE file_name='{}' and function_name='{}'".format(f_name, fi_name))
            f = q.fetchone()
            if f is not None:
                num=int(f[0])
            else:
                num = 0
            self.number_similar[true_labels[index]]=num

        return n_ids, n_true_labels

    @staticmethod
    def functions_ground_truth(labels, trunc_labels, indices, values, true_label):
        f_label = []
        y_true = []
        y_score = []
        for i, e in enumerate(indices):
            y_score.append(float(values[i]))
            l = trunc_labels[e]
            f_label.append(labels[e])
            if l == true_label:
                y_true.append(1)
            else:
                y_true.append(0)
        return f_label, y_true, y_score

    # this methos execute the test
    # it select the targets functions and it looks up for the targets in the entire db
    # the outcome is json file containing the top 200 similar for each target function.
    # the json file is an array and such array contains an entry for each target function
    # each entry is a triple (t0,t1,t2)
    # t0: an array that contains 1 at entry j if the entry j is similar to the target 0 otherwise
    # t1: the number of similar functions to the target in the whole db
    # t2: an array that at entry j contains the similarity score of the j-th most similar function to the target.
    #
    #
    def evaluate_precision_on_all_functions(self, compiler, opt):
        target_fcn_ids, true_labels = self.find_target_fcn(compiler, opt, 10000)
        batch = 1000
        trunc_labels = self.SE.trunc_labels
        labels = self.SE.labels

        info=[]

        for i in range(0, len(target_fcn_ids), batch):
            if i + batch > len(target_fcn_ids):
                batch = len(target_fcn_ids) - i
            target = self.SE.load_target(self.db_name, target_fcn_ids[i:i+batch])
            top_k = self.SE.top_k(target, self.k)

            for j in range(0, batch):
                f_label, a, b = SearchEngineEvaluator.functions_ground_truth(labels, trunc_labels, top_k.indices[j, :], top_k.values[j, :], true_labels[i+j])

                info.append((f_label, a, [true_labels[i + j], self.number_similar[true_labels[i + j]]],b))

        with open(compiler+'_'+opt+'_'+self.tables+'_top200.json', 'w') as outfile:
                json.dump(info, outfile)


def test(dbName, table, opt,x,k):

    print("k:{} - Table: {} - Opt: {}".format(k,table, opt))

    SEV = SearchEngineEvaluator(dbName, table, limit=2000000,k=k)
    SEV.evaluate_precision_on_all_functions(x, opt)

    print("-------------------------------------")


if __name__ == '__main__':

    random.seed(12345)

    dbName = Path(__file__).parent.parent / 'data/AMD64PostgreSQL.db'
    table = ['safe_embeddings']
    opt = ["O0", "O1", "O2", "O3"]
    for x in ['gcc-4.8',"clang-4.0",'gcc-7','clang-6.0']:
        for t in table:
            for o in opt:
                #p = Process(target=test, args=(dbName, t, o,x,200))
                #p.start()
                #p.join()
                pass
    test(dbName, table[0], "O0", 'gcc-7', 200)