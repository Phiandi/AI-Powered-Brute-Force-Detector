
def assign_severity(attempts):
    if attempts >= 7:
        return "HIGH"
    elif attempts == 6:
        return "MEDIUM"
    else:
        return "LOW"
