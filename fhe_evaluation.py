from eva import EvaProgram, Input, Output, evaluate
from eva.ckks import CKKSCompiler
from eva.seal import generate_keys
from eva.metric import valuation_mse

import time
import matplotlib.pyplot as plt

import pdb


def run_fhe(poly_function, name, input_scales, output_ranges):  # Evaluate the given polynomial function on 4096 encrypted values:
    iters = 10
    poly_modulus_degree = -1
    runtimes = []
    errors = []

    for itr in range(iters):
        start = time.time()

        poly = EvaProgram('Polynomial', vec_size=8192)
        with poly:
            x = Input('x')
            Output('y', poly_function(x))

        # Fixed-point scale for inputs, represented in number of bits:
        poly.set_input_scales(input_scales)
        # Maximum ranges of coefficients in outputs, represented in number of bits:
        poly.set_output_ranges(output_ranges)

        compiler = CKKSCompiler()
        # The compile method transforms the program in-place and returns:
        #   the compiled program
        #   encryption parameters for Microsoft SEAL with which the program can be executed
        #   a signature object, that specifies how inputs and outputs need to be encoded and decoded.
        compiled_poly, params, signature = compiler.compile(poly)
        # Inspect the compiled program by printing it in the DOT format for the Graphviz visualization software:
        with open("dot/" + name + ".dot", "w") as f:
            f.write(compiled_poly.to_DOT())
        if itr == 0:  # CKKS parameters are the same for each iteration, so only print them once
            poly_modulus_degree = params.poly_modulus_degree

        # Encryption keys can now be generated using the encryption parameters:
        public_ctx, secret_ctx = generate_keys(params)
        # Create and encrypt a dictionary of equally-spaced inputs between -5 and 5, using the public context and the program signature:
        inputs = {'x': [-5 + 10*i/compiled_poly.vec_size for i in range(compiled_poly.vec_size)]}
        encInputs = public_ctx.encrypt(inputs, signature)

        # Homomorphically execute the program with Microsoft SEAL:
        encOutputs = public_ctx.execute(compiled_poly, encInputs)

        # Decrypt the outputs using the secret context:
        outputs = secret_ctx.decrypt(encOutputs, signature)

        # Record runtime
        stop = time.time()
        runtimes.append(stop-start)

        # Execute an EVA program on unencrypted data:
        reference = evaluate(compiled_poly, inputs)
        # Compare the two sets of results with Mean Squared Error:
        errors.append(valuation_mse(outputs, reference))

    print('Polynomial modulus degree', poly_modulus_degree)
    print('Average runtime', sum(runtimes)/iters)
    print('Average MSE', sum(errors)/iters)

    return poly_modulus_degree, sum(runtimes)/iters, sum(errors)/iters


def chebyshev():
    poly_modulus_degrees = []
    runtimes = []
    errors = []

    deg, runtime, err = run_fhe(lambda x: -0.0533333333333333*x**2 + 2.29672856559844e-17*x + 1.0, 'cheby_poly2', 30, 20)
    poly_modulus_degrees.append(deg)
    runtimes.append(runtime)
    errors.append(err)

    deg, runtime, err = run_fhe(lambda x: 0.00512*x**4 - 2.35132185436292e-18*x**3 - 0.16*x**2 + 4.89858719658941e-17*x + 1.0, 'cheby_poly4', 30, 20)
    poly_modulus_degrees.append(deg)
    runtimes.append(runtime)
    errors.append(err)

    deg, runtime, err = run_fhe(lambda x: -0.000585142857142857*x**6 + 4.47870829402461e-19*x**5 + 0.0256*x**4 -
                                1.56754790290861e-17*x**3 - 0.32*x**2 + 1.22464679914735e-16*x + 1.0, 'cheby_poly6', 30, 20)
    poly_modulus_degrees.append(deg)
    runtimes.append(runtime)
    errors.append(err)

    deg, runtime, err = run_fhe(lambda x: 7.28177777777778e-5*x**8 - 1.13398289569287e-19*x**7 - 0.004096*x**6 + 5.46741753280491e-18*x**5 + 0.0768 *
                                x**4 - 7.97331723534049e-17*x**3 - 0.533333333333333*x**2 + 3.32221551472521e-16*x + 1.0, 'cheby_poly8', 30, 20)
    poly_modulus_degrees.append(deg)
    runtimes.append(runtime)
    errors.append(err)

    deg, runtime, err = run_fhe(lambda x: -9.53250909090909e-6*x**10 + 7.18014510949153e-21*x**9 + 0.00065536*x**8 - 4.38786645580038e-19*x**7 - 0.016384*x**6 +
                                9.25565580520393e-18*x**5 + 0.1792*x**4 - 7.71304650433661e-17*x**3 - 0.8*x**2 + 2.00860586050432e-16*x + 1.0, 'cheby_poly10', 30, 20)
    poly_modulus_degrees.append(deg)
    runtimes.append(runtime)
    errors.append(err)

    plt.figure()
    plt.plot(range(2, 11, 2), runtimes)
    plt.title('FHE Evaluation of Chebyshev Approximations')
    plt.xlabel('Degree')
    plt.ylabel('Runtime (s)')
    plt.ylim(bottom=0)
    plt.savefig('results/cheby_runtimes.png')

    with open("results/cheby_poly_modulus_degrees.txt", "w") as f:
        for deg in poly_modulus_degrees:
            f.write(f"{deg}\n")

    with open("results/cheby_errors.txt", "w") as f:
        for err in errors:
            f.write(f"{err}\n")

    return runtimes


def minimax():
    poly_modulus_degrees = []
    runtimes = []
    errors = []

    deg, runtime, err = run_fhe(lambda x: -0.024950527545258522*x**2 - 0.0987802999285526*x + 0.6237631886314631, 'mm_poly2', 30, 20)
    poly_modulus_degrees.append(deg)
    runtimes.append(runtime)
    errors.append(err)

    deg, runtime, err = run_fhe(lambda x: 0.00634038911137016*x**4 - 0.00407359817765997*x**3 - 0.18570010532765574*x**2 + 0.004335521937744174*x + 0.679759438585044, 'mm_poly4', 30, 20)
    poly_modulus_degrees.append(deg)
    runtimes.append(runtime)
    errors.append(err)

    deg, runtime, err = run_fhe(lambda x: -0.000620083289081901*x**6 + 0.002398532961841965*x**5 + 0.028858172428070823*x**4 - 0.07715912707437025 *
                                x**3 - 0.3861815224336235*x**2 + 0.5237883301907104*x + 1.3069816852010294, 'mm_poly6', 30, 20)
    poly_modulus_degrees.append(deg)
    runtimes.append(runtime)
    errors.append(err)

    deg, runtime, err = run_fhe(lambda x: 0.00020413319233468963*x**8 - 8.817535706168166e-05*x**7 - 0.010573893362360708*x**6 - 0.00407228575751848*x**5 +
                                0.17505735028396438*x**4 - 0.04890884127931118*x**3 - 1.0154403475418765*x**2 + 0.14688608966841082*x + 1.4527202922170603, 'mm_poly8', 30, 20)
    poly_modulus_degrees.append(deg)
    runtimes.append(runtime)
    errors.append(err)

    deg, runtime, err = run_fhe(lambda x: -2.284871020324586e-05*x**10 + 2.3527469896569213e-05*x**9 + 0.0015256601539810903*x**8-0.0012620994639159894*x**7 - 0.03634685322705485*x **
                                6 + 0.022623122816971705*x**5 + 0.3672986923385317*x**4 - 0.152714360742452235*x**3 - 1.436306679738091*x**2 + 0.29867430901628356*x + 1.4365038843115265, 'mm_poly10', 30, 20)
    poly_modulus_degrees.append(deg)
    runtimes.append(runtime)
    errors.append(err)

    plt.figure()
    plt.plot(range(2, 11, 2), runtimes)
    plt.title('FHE Evaluation of Minimax Approximations')
    plt.xlabel('Degree')
    plt.ylabel('Runtime (s)')
    plt.ylim(bottom=0)
    plt.savefig('results/mm_runtimes.png')

    with open("results/mm_poly_modulus_degrees.txt", "w") as f:
        for deg in poly_modulus_degrees:
            f.write(f"{deg}\n")

    with open("results/mm_errors.txt", "w") as f:
        for err in errors:
            f.write(f"{err}\n")

    return runtimes


if __name__ == "__main__":
    cheby_runtimes = chebyshev()
    mm_runtimes = minimax()

    plt.figure()
    plt.plot(range(2, 11, 2), cheby_runtimes, label='Chebyshev')
    plt.plot(range(2, 11, 2), mm_runtimes, label='Minimax')
    plt.xlabel('Degree')
    plt.ylabel('Runtime (s)')
    plt.ylim(bottom=0)
    plt.legend()
    plt.savefig('results/runtimes.png')
