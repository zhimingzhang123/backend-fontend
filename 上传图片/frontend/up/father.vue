<template>
  <div>
    <upload-img v-model="img"></upload-img>
  </div>
</template>

<script>
  import UploadImg from './index'

  export default {
    name: '',
    components:{UploadImg},
    data() {
      return {
        img: null
      }
    }
  }
</script>

<style scoped>

</style>
