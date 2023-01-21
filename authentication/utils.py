def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', None)
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[-1].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', None)

    return ip


def get_user_agent(request):
    # trim to 256 characters since thats the DB limit
    return request.META.get('HTTP_USER_AGENT', '')[:256]
