#!/bin/bash

javac -cp lib/junit-4.13.jar:lib/mockito-all-1.10.19.jar:.. *.java 

java -cp lib/junit-4.13.jar:lib/hamcrest-2.2.jar:lib/mockito-all-1.10.19.jar:..:. org.junit.runner.JUnitCore TestGroupServer