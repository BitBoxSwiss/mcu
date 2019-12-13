#!/usr/bin/env python3
import argparse
import base64
import os
import random
import struct
import sys

def main():
    parser = argparse.ArgumentParser(description='Generate random test cases for the base64 unit test.')
    parser.add_argument('--count', default=1000, type=int, help='Number of test cases to generate')
    parser.add_argument('--maxSize', default=1000, type=int, help='Maximum (binary) size of each test case')
    parser.add_argument('--seed', default=1234, type=int, help='Seed for the RNG.')
    parser.add_argument('--output', required=True, type=str, help='Output file')
    args = parser.parse_args()
    print("Generating {} test cases".format(args.count))
    print("Setting the random seed to {}".format(args.seed))
    random.seed(args.seed)
    testCases = []
    for i in range(args.count):
        testCaseSize = random.randrange(0, args.maxSize)
        testCaseBinary = os.urandom(testCaseSize)
        assert(len(testCaseBinary) == testCaseSize)
        testCases.append((testCaseBinary, base64.b64encode(testCaseBinary)))
    assert(len(testCases) == args.count)
    # Now dump the test data to file.
    # File format:
    #     - Two bytes length of the binary string (little endian)
    #     - Binary string
    #     - Two bytes length of the encoded string (little endian, no null terminator)
    #     - Encoded string (no null terminator)
    with open(args.output, 'wb') as f:
        f.write(struct.pack('<H', len(testCases)))
        for t in testCases:
            f.write(struct.pack('<H', len(t[0])))
            f.write(t[0])
            base64Bytes = t[1]
            f.write(struct.pack('<H', len(base64Bytes)))
            f.write(base64Bytes)
    print("Successfully dumped {} test cases.".format(len(testCases)))

if __name__=='__main__':
    main()
