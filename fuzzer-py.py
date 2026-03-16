#!/usr/bin/env python3
"""Coverage-guided fuzzer — mutates inputs to maximize code coverage."""
import sys,random,hashlib

class Fuzzer:
    def __init__(self,target,seed=42):
        self.target=target;self.rng=random.Random(seed)
        self.corpus=[];self.coverage=set();self.crashes=[]
    def mutate(self,data):
        d=bytearray(data);strat=self.rng.randint(0,4)
        if not d:d=bytearray([self.rng.randint(0,255)])
        elif strat==0:  # flip bit
            i=self.rng.randint(0,len(d)-1);d[i]^=(1<<self.rng.randint(0,7))
        elif strat==1:  # random byte
            i=self.rng.randint(0,len(d)-1);d[i]=self.rng.randint(0,255)
        elif strat==2:  # insert
            i=self.rng.randint(0,len(d));d.insert(i,self.rng.randint(0,255))
        elif strat==3:  # delete
            if len(d)>1:del d[self.rng.randint(0,len(d)-1)]
        elif strat==4:  # splice from corpus
            if self.corpus:
                other=self.rng.choice(self.corpus)
                i=self.rng.randint(0,len(d))
                j=self.rng.randint(0,max(1,len(other)))
                d=d[:i]+bytearray(other[:j])
        return bytes(d)
    def run(self,iterations=1000,seeds=None):
        if seeds:self.corpus.extend(seeds)
        if not self.corpus:self.corpus=[b'\x00']
        for i in range(iterations):
            parent=self.rng.choice(self.corpus)
            inp=self.mutate(parent)
            try:
                cov=self.target(inp)
                new_cov=cov-self.coverage
                if new_cov:
                    self.coverage|=new_cov
                    self.corpus.append(inp)
            except Exception as e:
                self.crashes.append((inp,str(e)))
        return {"coverage":len(self.coverage),"corpus":len(self.corpus),"crashes":len(self.crashes)}

def main():
    if len(sys.argv)>1 and sys.argv[1]=="--test":
        def target(data):
            cov=set()
            cov.add("start")
            if len(data)>2:
                cov.add("len>2")
                if data[0]==0x41:
                    cov.add("A")
                    if data[1]==0x42:
                        cov.add("AB")
                        if data[2]==0x43:
                            cov.add("ABC")
                            raise ValueError("found ABC!")
            return cov
        f=Fuzzer(target,seed=42)
        r=f.run(5000,seeds=[b"hello"])
        assert r["coverage"]>=3  # should find at least start, len>2, and one branch
        assert r["corpus"]>1
        # Coverage should grow
        f2=Fuzzer(lambda d:{len(d)},seed=0)
        r2=f2.run(500)
        assert r2["coverage"]>5  # should find various lengths
        print("All tests passed!")
    else:
        def target(data):
            cov={f"len={min(len(data),10)}"}
            if data and data[0]>128:cov.add("high")
            return cov
        f=Fuzzer(target);r=f.run(1000)
        print(f"Coverage: {r['coverage']}, Corpus: {r['corpus']}, Crashes: {r['crashes']}")
if __name__=="__main__":main()
