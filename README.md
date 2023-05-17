# SAFHE: Defending Against Backdoor and Gradient Inversion Attacks in Federated Learning

This repository contains the implementation and experiment code used to evaluate our SAFHE method (Secure Aggregation with Fully Homomorphic Encryption), a novel scheme to defend against both backdoor attacks and gradient inversion attacks in federated learning systems.
 
The code is organized across three files: 

1. `simulation.ipynb` provides implementations for two backdoor attacks, secure aggregation schemes, and a federated learning simulation. Additionally, it contains the results gathered and plots generated over the course of our experiments. For additional details on how to run a simulation, see the inline comments. 

2. `fhe-evaluation.py` contains code that performs the actual FHE evaluation of Chebyshev and Minimax polynomials, using a Python wrapper of the Microsoft SEAL framework. This was used to generate our performance and FHE accuracy results. 

3. `approximation_functions.ipynb` contains a simple library for generating Chebyshev and Minimax approximations of our target aggregation functions. After experimentation, the Chebyshev section was incorporated into `simulation.ipynb`.
