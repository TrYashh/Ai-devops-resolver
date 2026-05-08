from fastapi import APIRouter

router = APIRouter()


@router.get('/api/services')
async def get_services():

    return [
        {
            'name': 'backend',
            'cpu': 45,
            'memory': 60,
            'status': 'healthy'
        },
        {
            'name': 'mcp-server',
            'cpu': 22,
            'memory': 35,
            'status': 'healthy'
        },
        {
            'name': 'agent',
            'cpu': 55,
            'memory': 40,
            'status': 'healthy'
        }
    ]