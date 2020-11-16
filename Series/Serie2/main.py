
def pgcd(a,b):
    if(b == 0):
        return a
    else:
        return pgcd(b, a % b)



a = 36182736189736918736192873
b = 131556721028295178496

print("Le pgcd de " + str(a) + " et " + str(b) + " = " + str(pgcd(a, b)))