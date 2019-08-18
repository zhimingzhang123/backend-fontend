import request from '@/utils/request'

export function uploadOss() {
  return request({
    url: '/upload/',
    method: 'get',
  })
}
